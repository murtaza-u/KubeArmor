// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package monitor

import (
	"bytes"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	cle "github.com/cilium/ebpf"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type batchAuditEntry struct {
	key tp.BatchAuditAggKey
	val tp.BatchAuditAggVal
}

func (mon *SystemMonitor) UpdateBatchAuditInterval(interval int32) {
	mon.BatchAuditLock.Lock()
	defer mon.BatchAuditLock.Unlock()

	if mon.Logger != nil {
		mon.Logger.Debugf("UpdateBatchAuditInterval called with interval=%d", interval)
	}

	if interval <= 0 {
		if mon.BatchAuditStop != nil {
			close(mon.BatchAuditStop)
			mon.BatchAuditStop = nil
		}
		if mon.Logger != nil {
			mon.Logger.Debugf("BatchAudit interval disabled")
		}
		mon.BatchAuditInterval = 0
		return
	}

	if mon.BatchAuditInterval == interval {
		return
	}

	if mon.BatchAuditStop != nil {
		close(mon.BatchAuditStop)
		mon.BatchAuditStop = nil
	}

	mon.BatchAuditInterval = interval
	if mon.Logger != nil {
		mon.Logger.Debugf("BatchAudit interval set to %d seconds", interval)
	}
	mon.startBatchAuditTicker(interval)
}

func (mon *SystemMonitor) startBatchAuditTicker(interval int32) {
	stopCh := make(chan struct{})
	mon.BatchAuditStop = stopCh

	if mon.Logger != nil {
		mon.Logger.Debugf("Starting BatchAudit ticker interval=%d", interval)
	}

	go func(stop chan struct{}) {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-StopChan:
				return
			case <-stop:
				return
			case <-ticker.C:
				mon.FlushBatchAuditEvents()
			}
		}
	}(stopCh)
}

func (mon *SystemMonitor) getBatchAuditMap() (*cle.Map, error) {
	mon.BatchAuditMapLock.Lock()
	defer mon.BatchAuditMapLock.Unlock()

	if mon.BatchAuditMap != nil {
		return mon.BatchAuditMap, nil
	}

	mapPath := filepath.Join(kl.GetMapRoot(), "kubearmor_batch_audit_agg")
	batchMap, err := cle.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, err
	}
	mon.BatchAuditMap = batchMap
	return mon.BatchAuditMap, nil
}

func (mon *SystemMonitor) FlushBatchAuditEvents() {
	mon.BatchAuditFlushLock.Lock()
	defer mon.BatchAuditFlushLock.Unlock()

	batchMap, err := mon.getBatchAuditMap()
	if err != nil {
		if mon.Logger != nil {
			mon.Logger.Warnf("Failed to load batch audit map: %s", err.Error())
		}
		return
	}

	entries := []batchAuditEntry{}
	iter := batchMap.Iterate()
	for {
		var key tp.BatchAuditAggKey
		var val tp.BatchAuditAggVal
		if !iter.Next(&key, &val) {
			break
		}

		if val.SampleSize == 0 {
			_ = batchMap.Delete(&key)
			continue
		}
		entries = append(entries, batchAuditEntry{key: key, val: val})
	}

	if err := iter.Err(); err != nil {
		if mon.Logger != nil {
			mon.Logger.Warnf("Failed to iterate batch audit map: %s", err.Error())
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].val.FirstTs < entries[j].val.FirstTs
	})

	for _, entry := range entries {
		mon.flushBatchAuditEntry(entry)
		_ = batchMap.Delete(&entry.key)
	}
}

func (mon *SystemMonitor) flushBatchAuditEntry(entry batchAuditEntry) {
	sampleSize := int(entry.val.SampleSize)
	if sampleSize <= 0 {
		return
	}
	if sampleSize > tp.BatchAuditMaxBufferSize {
		sampleSize = tp.BatchAuditMaxBufferSize
	}
	sample2Size := int(entry.val.Sample2Size)
	if sample2Size < 0 {
		sample2Size = 0
	}
	if sampleSize+sample2Size > tp.BatchAuditMaxBufferSize {
		sample2Size = tp.BatchAuditMaxBufferSize - sampleSize
		if sample2Size < 0 {
			sample2Size = 0
		}
	}

	entryRaw := make([]byte, sampleSize)
	copy(entryRaw, entry.val.SampleData[:sampleSize])

	var retRaw []byte
	if sample2Size > 0 {
		retRaw = make([]byte, sample2Size)
		copy(retRaw, entry.val.SampleData[sampleSize:sampleSize+sample2Size])
	}

	if len(entryRaw) == 0 {
		return
	}

	dataBuff := bytes.NewBuffer(entryRaw)
	ctx, err := readContextFromBuff(dataBuff)
	if err != nil {
		return
	}

	containerID := ""
	if ctx.PidID != 0 && ctx.MntID != 0 {
		containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID)
		if containerID == "" {
			return
		}
		Containers := *(mon.Containers)
		ContainersLock := *(mon.ContainersLock)
		ContainersLock.RLock()
		namespace := Containers[containerID].NamespaceName
		if kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), namespace) {
			ContainersLock.RUnlock()
			return
		}
		ContainersLock.RUnlock()
	}

	if ctx.EventID == SysExecve || ctx.EventID == SysExecveAt {
		if len(retRaw) == 0 {
			return
		}
		log, ok := mon.buildExecLogFromBatch(entryRaw, retRaw, containerID)
		if !ok {
			return
		}
		log.PolicyHash = entry.key.PolicyHash
		log.PolicyMatched = true
		log.BatchAuditFlush = true
		if log.Type == "" {
			if containerID == "" {
				log.Type = "MatchedHostPolicy"
			} else {
				log.Type = "MatchedPolicy"
			}
		}
		log.Action = "BatchAudit"
		log.EventData = map[string]string{
			"batchAuditCount":   strconv.FormatUint(entry.val.Count, 10),
			"batchAuditFirstTs": strconv.FormatUint(entry.val.FirstTs, 10),
			"batchAuditLastTs":  strconv.FormatUint(entry.val.LastTs, 10),
		}
		if mon.Logger != nil {
			go mon.Logger.PushLog(log)
		}
		return
	}

	args, err := GetArgs(dataBuff, ctx.Argnum)
	if err != nil {
		return
	}

	var hashes HashContext
	if ctx.Hash == uint8(1) {
		hashes, _ = GetHashes(dataBuff)
	}

	msg := ContextCombined{
		ContainerID:     containerID,
		ContextSys:      ctx,
		ContextArgs:     args,
		HashData:        hashes,
		RawData:         entryRaw,
		BatchAuditFlush: true,
		PolicyHash:      entry.key.PolicyHash,
		PolicyMatched:   true,
	}

	log, ok := mon.buildLogFromContext(msg)
	if !ok {
		return
	}
	if log.Type == "" {
		if containerID == "" {
			log.Type = "MatchedHostPolicy"
		} else {
			log.Type = "MatchedPolicy"
		}
	}
	log.Action = "BatchAudit"
	log.EventData = map[string]string{
		"batchAuditCount":   strconv.FormatUint(entry.val.Count, 10),
		"batchAuditFirstTs": strconv.FormatUint(entry.val.FirstTs, 10),
		"batchAuditLastTs":  strconv.FormatUint(entry.val.LastTs, 10),
	}
	if mon.Logger != nil {
		go mon.Logger.PushLog(log)
	}
}
