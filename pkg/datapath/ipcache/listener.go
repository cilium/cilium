// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// monitorNotify is an interface to notify the monitor about ipcache changes.
type monitorNotify interface {
	SendEvent(typ int, event any) error
}

type Map interface {
	Update(key bpf.MapKey, value bpf.MapValue) error
	Delete(key bpf.MapKey) error
}

// BPFListener implements the ipcache.IPIdentityMappingBPFListener
// interface with an IPCache store that is backed by BPF maps.
type BPFListener struct {
	logger *slog.Logger
	// bpfMap is the BPF map that this listener will update when events are
	// received from the IPCache.
	bpfMap Map

	// monitorNotify is used to notify the monitor about ipcache updates
	monitorNotify monitorNotify

	// tunnelConf holds the tunneling configuration.
	tunnelConf tunnel.Config

	localNodeStore *node.LocalNodeStore

	mu                 lock.Mutex
	tunnelEndpoints    map[string]net.IP
	pendingByHostIP    map[string]map[string]pendingEntry
	programmedByHostIP map[string]map[string]pendingEntry
	prefixToHostIP     map[string]string
}

// NewListener returns a new listener to push IPCache entries into BPF maps.
func NewListener(m Map, mn monitorNotify, tunnelConf tunnel.Config, logger *slog.Logger, localNodeStore *node.LocalNodeStore) *BPFListener {
	return &BPFListener{
		logger:             logger,
		bpfMap:             m,
		monitorNotify:      mn,
		tunnelConf:         tunnelConf,
		localNodeStore:     localNodeStore,
		tunnelEndpoints:    make(map[string]net.IP),
		pendingByHostIP:    make(map[string]map[string]pendingEntry),
		programmedByHostIP: make(map[string]map[string]pendingEntry),
		prefixToHostIP:     make(map[string]string),
	}
}

type pendingEntry struct {
	cidrCluster   cmtypes.PrefixCluster
	oldHostIP     net.IP
	newHostIP     net.IP
	oldID         *ipcache.Identity
	newID         ipcache.Identity
	encryptKey    uint8
	k8sMeta       *ipcache.K8sMetadata
	endpointFlags uint8
}

func (l *BPFListener) notifyMonitor(modType ipcache.CacheModification,
	prefix netip.Prefix, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity,
	newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	var (
		k8sNamespace, k8sPodName string
		newIdentity, oldIdentity uint32
		oldIdentityPtr           *uint32
	)

	if l.monitorNotify == nil {
		return
	}

	if k8sMeta != nil {
		k8sNamespace = k8sMeta.Namespace
		k8sPodName = k8sMeta.PodName
	}

	newIdentity = newID.ID.Uint32()
	if oldID != nil {
		oldIdentity = oldID.ID.Uint32()
		oldIdentityPtr = &oldIdentity
	}

	switch modType {
	case ipcache.Upsert:
		msg := monitorAPI.IPCacheUpsertedMessage(prefix.String(), newIdentity, oldIdentityPtr,
			newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
		l.monitorNotify.SendEvent(monitorAPI.MessageTypeAgent, msg)
	case ipcache.Delete:
		msg := monitorAPI.IPCacheDeletedMessage(prefix.String(), newIdentity, oldIdentityPtr,
			newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
		l.monitorNotify.SendEvent(monitorAPI.MessageTypeAgent, msg)
	}
}

// OnIPIdentityCacheChange is called whenever there is a change of state in the
// IPCache (pkg/ipcache).
// TODO (FIXME): GH-3161.
//
// 'oldIPIDPair' is ignored here, because in the BPF maps an update for the
// IP->ID mapping will replace any existing contents; knowledge of the old pair
// is not required to upsert the new pair.
func (l *BPFListener) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	prefix := cidrCluster.AsPrefix()

	scopedLog := l.logger.With(
		logfields.IPAddr, prefix,
		logfields.Identity, newID,
		logfields.Modification, modType,
	)

	scopedLog.Debug("Daemon notified of IP-Identity cache state change")

	l.notifyMonitor(modType, prefix, oldHostIP, newHostIP, oldID, newID, encryptKey, k8sMeta)

	// TODO - see if we can factor this into an interface under something like
	// pkg/datapath instead of in the daemon directly so that the code is more
	// logically located.

	// Update BPF Maps.
	entry := pendingEntry{
		cidrCluster:   cidrCluster,
		oldHostIP:     oldHostIP,
		newHostIP:     newHostIP,
		oldID:         oldID,
		newID:         newID,
		encryptKey:    encryptKey,
		k8sMeta:       k8sMeta,
		endpointFlags: endpointFlags,
	}

	switch modType {
	case ipcache.Upsert:
		originalHostIP, effectiveHostIP, shouldDelay := l.prepareUpsert(entry)
		if shouldDelay {
			scopedLog.Debug("Delaying ipcache map update until tunnel endpoint mapping is known",
				logfields.TunnelPeer, originalHostIP,
			)
			return
		}
		err := l.applyUpsert(entry, effectiveHostIP)
		if err != nil {
			scopedLog.Warn(
				"unable to update bpf map",
				logfields.Error, err,
			)
		}
	case ipcache.Delete:
		if l.dropPendingOrProgrammed(cidrCluster) {
			return
		}
		key := ipcacheMap.NewKey(prefix, uint16(cidrCluster.ClusterID()))
		err := l.bpfMap.Delete(&key)
		if err != nil {
			scopedLog.Warn(
				"unable to delete from bpf map",
				logfields.Key, key,
			)
		}
	default:
		scopedLog.Warn("cache modification type not supported")
	}
}

func (l *BPFListener) OnTunnelEndpointMappingUpsert(from, to net.IP) {
	l.mu.Lock()
	l.tunnelEndpoints[from.String()] = to
	l.mu.Unlock()

	entries := l.takeEntries(l.pendingByHostIP, from.String())
	if len(entries) == 0 {
		return
	}

	for _, entry := range entries {
		_, effectiveHostIP, shouldDelay := l.resolveHostIP(entry.newHostIP)
		if shouldDelay {
			l.storeEntry(l.pendingByHostIP, from.String(), entry)
			continue
		}
		_ = l.applyUpsert(entry, effectiveHostIP)
	}
}

func (l *BPFListener) OnTunnelEndpointMappingDelete(from net.IP) {
	l.mu.Lock()
	delete(l.tunnelEndpoints, from.String())
	l.mu.Unlock()

	entries := l.takeEntries(l.programmedByHostIP, from.String())
	if len(entries) == 0 {
		return
	}

	for _, entry := range entries {
		key := ipcacheMap.NewKey(entry.cidrCluster.AsPrefix(), uint16(entry.cidrCluster.ClusterID()))
		_ = l.bpfMap.Delete(&key)
		l.storeEntry(l.pendingByHostIP, from.String(), entry)
	}
}

func (l *BPFListener) prepareUpsert(entry pendingEntry) (originalHostIP, effectiveHostIP net.IP, shouldDelay bool) {
	originalHostIP, effectiveHostIP, shouldDelay = l.resolveHostIP(entry.newHostIP)
	prefixKey := entry.cidrCluster.String()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.removeTrackedEntryLocked(prefixKey)
	if shouldDelay {
		l.storeEntryLocked(l.pendingByHostIP, originalHostIP.String(), entry)
		return originalHostIP, nil, true
	}
	if originalHostIP != nil && !originalHostIP.IsUnspecified() {
		l.storeEntryLocked(l.programmedByHostIP, originalHostIP.String(), entry)
	}

	return originalHostIP, effectiveHostIP, false
}

func (l *BPFListener) resolveHostIP(hostIP net.IP) (originalHostIP, effectiveHostIP net.IP, shouldDelay bool) {
	if hostIP == nil || hostIP.IsUnspecified() {
		return nil, nil, false
	}

	originalHostIP = hostIP
	effectiveHostIP = hostIP

	if !option.Config.EnableFloatingTunnelEndpoint {
		return originalHostIP, effectiveHostIP, false
	}

	l.mu.Lock()
	mappedIP, ok := l.tunnelEndpoints[hostIP.String()]
	l.mu.Unlock()
	if ok {
		return originalHostIP, mappedIP, false
	}

	ln, err := l.localNodeStore.Get(context.Background())
	if err != nil {
		logging.Fatal(l.logger, "Failed to retrieve local node")
	}

	switch l.underlayProtocol(hostIP) {
	case tunnel.IPv4:
		nodeIPv4 := ln.GetNodeIP(false)
		if ip4 := hostIP.To4(); ip4 != nil && !ip4.Equal(nodeIPv4) {
			return originalHostIP, nil, true
		}
	case tunnel.IPv6:
		nodeIPv6 := ln.GetNodeIP(true)
		if !hostIP.Equal(nodeIPv6) {
			return originalHostIP, nil, true
		}
	}

	return originalHostIP, effectiveHostIP, false
}

func (l *BPFListener) applyUpsert(entry pendingEntry, hostIP net.IP) error {
	key := ipcacheMap.NewKey(entry.cidrCluster.AsPrefix(), uint16(entry.cidrCluster.ClusterID()))

	var tunnelEndpoint netip.Addr
	if hostIP != nil {
		ln, err := l.localNodeStore.Get(context.Background())
		if err != nil {
			logging.Fatal(l.logger, "Failed to retrieve local node")
		}

		switch l.underlayProtocol(hostIP) {
		case tunnel.IPv4:
			nodeIPv4 := ln.GetNodeIP(false)
			if ip4 := hostIP.To4(); ip4 != nil && !ip4.Equal(nodeIPv4) {
				tunnelEndpoint, _ = netipx.FromStdIP(ip4)
			}
		case tunnel.IPv6:
			nodeIPv6 := ln.GetNodeIP(true)
			if !hostIP.Equal(nodeIPv6) {
				tunnelEndpoint, _ = netipx.FromStdIP(hostIP)
			}
		}
	}

	value := ipcacheMap.NewValue(uint32(entry.newID.ID), tunnelEndpoint, entry.encryptKey,
		ipcacheMap.RemoteEndpointInfoFlags(entry.endpointFlags))
	return l.bpfMap.Update(&key, &value)
}

func (l *BPFListener) underlayProtocol(hostIP net.IP) tunnel.UnderlayProtocol {
	switch proto := l.tunnelConf.UnderlayProtocol(); proto {
	case tunnel.IPv4, tunnel.IPv6:
		return proto
	default:
		if hostIP.To4() != nil {
			return tunnel.IPv4
		}
		return tunnel.IPv6
	}
}

func (l *BPFListener) dropPendingOrProgrammed(cidrCluster cmtypes.PrefixCluster) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.removeTrackedEntryLocked(cidrCluster.String())
}

func (l *BPFListener) takeEntries(source map[string]map[string]pendingEntry, hostIP string) []pendingEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	prefixes, ok := source[hostIP]
	if !ok {
		return nil
	}
	delete(source, hostIP)

	entries := make([]pendingEntry, 0, len(prefixes))
	for prefixKey, entry := range prefixes {
		delete(l.prefixToHostIP, prefixKey)
		entries = append(entries, entry)
	}
	return entries
}

func (l *BPFListener) storeEntry(target map[string]map[string]pendingEntry, hostIP string, entry pendingEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.storeEntryLocked(target, hostIP, entry)
}

func (l *BPFListener) storeEntryLocked(target map[string]map[string]pendingEntry, hostIP string, entry pendingEntry) {
	prefixKey := entry.cidrCluster.String()
	if target[hostIP] == nil {
		target[hostIP] = make(map[string]pendingEntry)
	}
	target[hostIP][prefixKey] = entry
	l.prefixToHostIP[prefixKey] = hostIP
}

func (l *BPFListener) removeTrackedEntryLocked(prefixKey string) bool {
	hostIP, ok := l.prefixToHostIP[prefixKey]
	if !ok {
		return false
	}
	delete(l.prefixToHostIP, prefixKey)

	for _, tracked := range []map[string]map[string]pendingEntry{l.pendingByHostIP, l.programmedByHostIP} {
		if entries, ok := tracked[hostIP]; ok {
			delete(entries, prefixKey)
			if len(entries) == 0 {
				delete(tracked, hostIP)
			}
		}
	}

	return true
}
