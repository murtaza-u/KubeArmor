// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package feeder

import (
	"path/filepath"
	"strconv"
	"strings"

	cle "github.com/cilium/ebpf"

	common "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type batchAuditPolicyMeta struct {
	Namespace  string
	PolicyName string
	Scope      string
	Severity   string
	Tags       []string
	Message    string
}

type batchAuditOuterKey struct {
	PidNs uint32
	MntNs uint32
}

type batchAuditPolicyKey struct {
	OKey batchAuditOuterKey
	Rule tp.BatchAuditRuleKey
}

const (
	batchAuditProcess = 0
	batchAuditFile    = 1
)

const (
	batchAuditRuleExec      = 1 << 0
	batchAuditRuleWrite     = 1 << 1
	batchAuditRuleRead      = 1 << 2
	batchAuditRuleOwner     = 1 << 3
	batchAuditRuleDir       = 1 << 4
	batchAuditRuleRecursive = 1 << 5
	batchAuditRuleHint      = 1 << 6
)

func (fd *Feeder) getBatchAuditPolicyMap() (*cle.Map, error) {
	fd.BatchAuditPolicyMapLock.Lock()
	defer fd.BatchAuditPolicyMapLock.Unlock()

	if fd.BatchAuditPolicyMap != nil {
		return fd.BatchAuditPolicyMap, nil
	}

	mapPath := filepath.Join(common.GetMapRoot(), "kubearmor_batch_audit_policies")
	polMap, err := cle.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, err
	}
	fd.BatchAuditPolicyMap = polMap
	return fd.BatchAuditPolicyMap, nil
}

func (fd *Feeder) updateBatchAuditPolicyMeta(policyHash uint64, meta batchAuditPolicyMeta) {
	fd.BatchAuditPolicyMetaLock.Lock()
	fd.BatchAuditPolicyMeta[policyHash] = meta
	fd.BatchAuditPolicyMetaLock.Unlock()
}

func (fd *Feeder) deleteBatchAuditPolicyMeta(policyHash uint64) {
	fd.BatchAuditPolicyMetaLock.Lock()
	delete(fd.BatchAuditPolicyMeta, policyHash)
	fd.BatchAuditPolicyMetaLock.Unlock()
}

func (fd *Feeder) deleteBatchAuditAggForPolicyHash(policyHash uint64) {
	batchMap, err := fd.getBatchAuditMap()
	if err != nil {
		return
	}

	iter := batchMap.Iterate()
	for {
		var key tp.BatchAuditAggKey
		var val tp.BatchAuditAggVal
		if !iter.Next(&key, &val) {
			break
		}
		if key.PolicyHash == policyHash {
			_ = batchMap.Delete(&key)
		}
	}
}

func (fd *Feeder) cleanupStaleBatchAuditAgg(scope, namespace string, keep map[uint64]struct{}) {
	stale := make([]uint64, 0)

	fd.BatchAuditPolicyMetaLock.RLock()
	for hash, meta := range fd.BatchAuditPolicyMeta {
		if meta.Scope != scope {
			continue
		}
		if meta.Namespace != namespace {
			continue
		}
		if _, ok := keep[hash]; ok {
			continue
		}
		stale = append(stale, hash)
	}
	fd.BatchAuditPolicyMetaLock.RUnlock()

	for _, hash := range stale {
		fd.deleteBatchAuditPolicyMeta(hash)
		fd.deleteBatchAuditAggForPolicyHash(hash)
	}
}

func (fd *Feeder) policyHashFor(scope, namespace, policyName string) uint64 {
	key := namespace + ":" + policyName + ":" + scope
	return hashString64(key)
}

func ruleAction(policyAction, ruleAction string) string {
	if ruleAction != "" {
		return ruleAction
	}
	return policyAction
}

func setKeyPath(dst *[200]byte, val string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst[:], []byte(val))
}

func setKeySource(dst *[200]byte, val string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst[:], []byte(val))
}

func addBatchAuditRule(m map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal, key tp.BatchAuditRuleKey, mask [2]uint16, policyHash uint64) {
	m[key] = tp.BatchAuditRuleVal{
		PolicyHash:  policyHash,
		ProcessMask: mask[batchAuditProcess],
		FileMask:    mask[batchAuditFile],
	}
}

func dirToBatchAuditMap(idx int, p, src string, m map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal, mask [2]uint16, policyHash uint64) {
	var key tp.BatchAuditRuleKey
	if src != "" {
		setKeySource(&key.Source, src)
	}
	parts := strings.Split(p, "/")

	var pth [200]byte
	setKeyPath(&pth, strings.Join(parts[0:len(parts)-1], "/"))
	key.Path = pth
	addBatchAuditRule(m, key, mask, policyHash)

	setKeyPath(&key.Path, p)

	mask[idx] = mask[idx] | batchAuditRuleDir
	if oldval, ok := m[key]; ok {
		if oldval.ProcessMask&batchAuditRuleHint != 0 || oldval.FileMask&batchAuditRuleHint != 0 {
			mask[idx] = mask[idx] | batchAuditRuleHint
		}
	}
	addBatchAuditRule(m, key, mask, policyHash)

	for i := 1; i < len(parts)-1; i++ {
		var hintKey tp.BatchAuditRuleKey
		mask[idx] = mask[idx] &^ batchAuditRuleDir
		mask[idx] = mask[idx] | batchAuditRuleHint
		hint := strings.Join(parts[0:i], "/") + "/"
		setKeyPath(&hintKey.Path, hint)
		if src != "" {
			setKeySource(&hintKey.Source, src)
		}
		if oldval, ok := m[hintKey]; ok {
			if oldval.ProcessMask&batchAuditRuleDir != 0 || oldval.FileMask&batchAuditRuleDir != 0 {
				mask[idx] = mask[idx] | batchAuditRuleHint
			}
		}
		addBatchAuditRule(m, hintKey, mask, policyHash)
	}
}

func (fd *Feeder) buildBatchAuditRulesForPolicy(scope string, secPolicy tp.SecuritySpec, policyName, namespace string) (map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal, uint64, bool) {
	rules := map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal{}
	policyHash := fd.policyHashFor(scope, namespace, policyName)

	added := false

	for _, path := range secPolicy.Process.MatchPaths {
		action := ruleAction(secPolicy.Action, path.Action)
		if action != "BatchAudit" {
			continue
		}
		added = true

		var mask [2]uint16
		mask[batchAuditProcess] = mask[batchAuditProcess] | batchAuditRuleExec
		if path.OwnerOnly {
			mask[batchAuditProcess] = mask[batchAuditProcess] | batchAuditRuleOwner
		}
		if len(path.FromSource) == 0 {
			var key tp.BatchAuditRuleKey
			if len(path.ExecName) > 0 {
				setKeyPath(&key.Path, path.ExecName)
			} else {
				setKeyPath(&key.Path, path.Path)
			}
			addBatchAuditRule(rules, key, mask, policyHash)
			continue
		}
		for _, src := range path.FromSource {
			if len(src.Path) == 0 {
				continue
			}
			var key tp.BatchAuditRuleKey
			if len(path.ExecName) > 0 {
				setKeyPath(&key.Path, path.ExecName)
			} else {
				setKeyPath(&key.Path, path.Path)
			}
			setKeySource(&key.Source, src.Path)
			addBatchAuditRule(rules, key, mask, policyHash)
		}
	}

	for _, dir := range secPolicy.Process.MatchDirectories {
		action := ruleAction(secPolicy.Action, dir.Action)
		if action != "BatchAudit" {
			continue
		}
		added = true

		var mask [2]uint16
		mask[batchAuditProcess] = mask[batchAuditProcess] | batchAuditRuleExec
		if dir.OwnerOnly {
			mask[batchAuditProcess] = mask[batchAuditProcess] | batchAuditRuleOwner
		}
		if dir.Recursive {
			mask[batchAuditProcess] = mask[batchAuditProcess] | batchAuditRuleRecursive
		}
		if len(dir.FromSource) == 0 {
			dirToBatchAuditMap(batchAuditProcess, dir.Directory, "", rules, mask, policyHash)
			continue
		}
		for _, src := range dir.FromSource {
			if len(src.Path) == 0 {
				continue
			}
			dirToBatchAuditMap(batchAuditProcess, dir.Directory, src.Path, rules, mask, policyHash)
		}
	}

	for _, path := range secPolicy.File.MatchPaths {
		action := ruleAction(secPolicy.Action, path.Action)
		if action != "BatchAudit" {
			continue
		}
		added = true

		var mask [2]uint16
		mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleRead
		if !path.ReadOnly {
			mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleWrite
		}
		if path.OwnerOnly {
			mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleOwner
		}
		if len(path.FromSource) == 0 {
			var key tp.BatchAuditRuleKey
			setKeyPath(&key.Path, path.Path)
			addBatchAuditRule(rules, key, mask, policyHash)
			continue
		}
		for _, src := range path.FromSource {
			if len(src.Path) == 0 {
				continue
			}
			var key tp.BatchAuditRuleKey
			setKeyPath(&key.Path, path.Path)
			setKeySource(&key.Source, src.Path)
			addBatchAuditRule(rules, key, mask, policyHash)
		}
	}

	for _, dir := range secPolicy.File.MatchDirectories {
		action := ruleAction(secPolicy.Action, dir.Action)
		if action != "BatchAudit" {
			continue
		}
		added = true

		var mask [2]uint16
		mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleRead
		if !dir.ReadOnly {
			mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleWrite
		}
		if dir.OwnerOnly {
			mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleOwner
		}
		if dir.Recursive {
			mask[batchAuditFile] = mask[batchAuditFile] | batchAuditRuleRecursive
		}
		if len(dir.FromSource) == 0 {
			dirToBatchAuditMap(batchAuditFile, dir.Directory, "", rules, mask, policyHash)
			continue
		}
		for _, src := range dir.FromSource {
			if len(src.Path) == 0 {
				continue
			}
			dirToBatchAuditMap(batchAuditFile, dir.Directory, src.Path, rules, mask, policyHash)
		}
	}

	if added {
		meta := batchAuditPolicyMeta{
			Namespace:  namespace,
			PolicyName: policyName,
			Scope:      scope,
			Severity:   strconv.Itoa(secPolicy.Severity),
			Tags:       secPolicy.Tags,
			Message:    secPolicy.Message,
		}
		fd.updateBatchAuditPolicyMeta(policyHash, meta)
	}

	return rules, policyHash, added
}

func (fd *Feeder) setBatchAuditPolicyMap(key common.OuterKey, rules map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal) {
	polMap, err := fd.getBatchAuditPolicyMap()
	if err != nil {
		fd.Warnf("Failed to load batch audit policy map: %s", err.Error())
		return
	}

	okey := batchAuditOuterKey{PidNs: key.PidNs, MntNs: key.MntNs}
	fd.deleteBatchAuditPolicyEntries(polMap, okey)

	if len(rules) == 0 {
		return
	}

	for k, v := range rules {
		keyCopy := batchAuditPolicyKey{OKey: okey, Rule: k}
		valCopy := v
		if err := polMap.Update(&keyCopy, &valCopy, cle.UpdateAny); err != nil {
			fd.Warnf("Failed to update batch audit policy map: %s", err.Error())
		}
	}
}

func (fd *Feeder) deleteBatchAuditPolicyEntries(polMap *cle.Map, okey batchAuditOuterKey) {
	iter := polMap.Iterate()
	for {
		var key batchAuditPolicyKey
		var val tp.BatchAuditRuleVal
		if !iter.Next(&key, &val) {
			break
		}
		if key.OKey.PidNs == okey.PidNs && key.OKey.MntNs == okey.MntNs {
			_ = polMap.Delete(&key)
		}
	}
}

func (fd *Feeder) deleteBatchAuditPolicyMap(key common.OuterKey) {
	polMap, err := fd.getBatchAuditPolicyMap()
	if err != nil {
		return
	}

	okey := batchAuditOuterKey{PidNs: key.PidNs, MntNs: key.MntNs}
	fd.deleteBatchAuditPolicyEntries(polMap, okey)
}

func (fd *Feeder) UpdateBatchAuditPoliciesForEndpoint(action string, endPoint tp.EndPoint) {
	if action == "DELETED" {
		for _, containerID := range endPoint.Containers {
			if ns, ok := fd.ContainerNsKey[containerID]; ok {
				fd.deleteBatchAuditPolicyMap(ns)
			}
		}
		for _, secPolicy := range endPoint.SecurityPolicies {
			policyHash := fd.policyHashFor("container", endPoint.NamespaceName, secPolicy.Metadata["policyName"])
			fd.deleteBatchAuditPolicyMeta(policyHash)
			fd.deleteBatchAuditAggForPolicyHash(policyHash)
		}
		return
	}

	rules := map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal{}
	hasBatchAudit := false
	for _, secPolicy := range endPoint.SecurityPolicies {
		if len(secPolicy.Spec.AppArmor) > 0 {
			continue
		}
		name := secPolicy.Metadata["policyName"]
		pRules, policyHash, added := fd.buildBatchAuditRulesForPolicy("container", secPolicy.Spec, name, endPoint.NamespaceName)
		if added {
			hasBatchAudit = true
		} else {
			fd.deleteBatchAuditPolicyMeta(policyHash)
			fd.deleteBatchAuditAggForPolicyHash(policyHash)
		}
		for k, v := range pRules {
			if existing, ok := rules[k]; ok && existing.PolicyHash != v.PolicyHash {
				fd.Warnf("BatchAudit rule collision for policy %s/%s; keeping existing policy hash %x over %x", endPoint.NamespaceName, name, existing.PolicyHash, v.PolicyHash)
				continue
			}
			rules[k] = v
		}
	}

	if !hasBatchAudit {
		for _, containerID := range endPoint.Containers {
			if ns, ok := fd.ContainerNsKey[containerID]; ok {
				fd.deleteBatchAuditPolicyMap(ns)
			}
		}
		return
	}

	for _, containerID := range endPoint.Containers {
		if ns, ok := fd.ContainerNsKey[containerID]; ok {
			fd.setBatchAuditPolicyMap(ns, rules)
		}
	}
}

func (fd *Feeder) UpdateBatchAuditPoliciesForHost(action string, secPolicies []tp.HostSecurityPolicy) {
	interval := minBatchAuditIntervalForHostPolicies(secPolicies)
	fd.updateBatchAuditInterval(fd.Node.NodeName, interval, action)

	if action == "DELETED" {
		fd.deleteBatchAuditPolicyMap(common.OuterKey{PidNs: 0, MntNs: 0})
		for _, secPolicy := range secPolicies {
			policyHash := fd.policyHashFor("host", "", secPolicy.Metadata["policyName"])
			fd.deleteBatchAuditPolicyMeta(policyHash)
			fd.deleteBatchAuditAggForPolicyHash(policyHash)
		}
		fd.cleanupStaleBatchAuditAgg("host", "", map[uint64]struct{}{})
		return
	}

	rules := map[tp.BatchAuditRuleKey]tp.BatchAuditRuleVal{}

	hasBatchAudit := false
	currentHashes := map[uint64]struct{}{}
	for _, secPolicy := range secPolicies {
		if len(secPolicy.Spec.AppArmor) > 0 {
			continue
		}
		name := secPolicy.Metadata["policyName"]
		spec := tp.SecuritySpec{
			Process:  secPolicy.Spec.Process,
			File:     secPolicy.Spec.File,
			Severity: secPolicy.Spec.Severity,
			Tags:     secPolicy.Spec.Tags,
			Message:  secPolicy.Spec.Message,
			Action:   secPolicy.Spec.Action,
		}
		pRules, policyHash, added := fd.buildBatchAuditRulesForPolicy("host", spec, name, "")
		if added {
			hasBatchAudit = true
			currentHashes[policyHash] = struct{}{}
		} else {
			fd.deleteBatchAuditPolicyMeta(policyHash)
			fd.deleteBatchAuditAggForPolicyHash(policyHash)
		}
		for k, v := range pRules {
			if existing, ok := rules[k]; ok && existing.PolicyHash != v.PolicyHash {
				fd.Warnf("BatchAudit rule collision for host policy %s; keeping existing policy hash %x over %x", name, existing.PolicyHash, v.PolicyHash)
				continue
			}
			rules[k] = v
		}
	}

	if !hasBatchAudit {
		fd.deleteBatchAuditPolicyMap(common.OuterKey{PidNs: 0, MntNs: 0})
		fd.cleanupStaleBatchAuditAgg("host", "", map[uint64]struct{}{})
		return
	}

	fd.setBatchAuditPolicyMap(common.OuterKey{PidNs: 0, MntNs: 0}, rules)
	fd.cleanupStaleBatchAuditAgg("host", "", currentHashes)
}
