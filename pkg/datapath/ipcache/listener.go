// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-ipcache")

// datapath is an interface to the datapath implementation, used to apply
// changes that are made within this module.
type datapath interface {
	TriggerReloadWithoutCompile(reason string) (*sync.WaitGroup, error)
}

// monitorNotify is an interface to notify the monitor about ipcache changes.
type monitorNotify interface {
	SendNotification(msg monitorAPI.AgentNotifyMessage) error
}

// BPFListener implements the ipcache.IPIdentityMappingBPFListener
// interface with an IPCache store that is backed by BPF maps.
//
// One listener is shared between callers of OnIPIdentityCacheChange() and the
// controller launched from OnIPIdentityCacheGC(). However, The listener is not
// updated after initialization so no locking is provided for access.
type BPFListener struct {
	// bpfMap is the BPF map that this listener will update when events are
	// received from the IPCache.
	bpfMap *ipcacheMap.Map

	// datapath allows this listener to trigger BPF program regeneration.
	datapath datapath

	// monitorNotify is used to notify the monitor about ipcache updates
	monitorNotify monitorNotify

	ipcache *ipcache.IPCache
}

func newListener(m *ipcacheMap.Map, d datapath, mn monitorNotify, ipc *ipcache.IPCache) *BPFListener {
	return &BPFListener{
		bpfMap:        m,
		datapath:      d,
		monitorNotify: mn,
		ipcache:       ipc,
	}
}

// NewListener returns a new listener to push IPCache entries into BPF maps.
func NewListener(d datapath, mn monitorNotify, ipc *ipcache.IPCache) *BPFListener {
	return newListener(ipcacheMap.IPCacheMap(), d, mn, ipc)
}

func (l *BPFListener) notifyMonitor(modType ipcache.CacheModification,
	cidr net.IPNet, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity,
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
		msg := monitorAPI.IPCacheUpsertedMessage(cidr.String(), newIdentity, oldIdentityPtr,
			newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
		l.monitorNotify.SendNotification(msg)
	case ipcache.Delete:
		msg := monitorAPI.IPCacheDeletedMessage(cidr.String(), newIdentity, oldIdentityPtr,
			newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
		l.monitorNotify.SendNotification(msg)
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
	encryptKey uint8, nodeID uint16, k8sMeta *ipcache.K8sMetadata) {
	cidr := cidrCluster.AsIPNet()

	scopedLog := log
	if option.Config.Debug {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.IPAddr:       cidr,
			logfields.Identity:     newID,
			logfields.Modification: modType,
		})
	}

	scopedLog.Debug("Daemon notified of IP-Identity cache state change")

	l.notifyMonitor(modType, cidr, oldHostIP, newHostIP, oldID, newID, encryptKey, k8sMeta)

	// TODO - see if we can factor this into an interface under something like
	// pkg/datapath instead of in the daemon directly so that the code is more
	// logically located.

	// Update BPF Maps.

	key := ipcacheMap.NewKey(cidr.IP, cidr.Mask, 0)

	switch modType {
	case ipcache.Upsert:
		value := ipcacheMap.RemoteEndpointInfo{
			SecurityIdentity: uint32(newID.ID),
			Key:              encryptKey,
			NodeID:           nodeID,
		}

		if newHostIP != nil {
			// If the hostIP is specified and it doesn't point to
			// the local host, then the ipcache should be populated
			// with the hostIP so that this traffic can be guided
			// to a tunnel endpoint destination.
			nodeIPv4 := node.GetIPv4()
			if ip4 := newHostIP.To4(); ip4 != nil && !ip4.Equal(nodeIPv4) {
				copy(value.TunnelEndpoint[:], ip4)
			}
		}
		err := l.bpfMap.Update(&key, &value)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"key":                  key.String(),
				"value":                value.String(),
				logfields.IPAddr:       cidr,
				logfields.Identity:     newID,
				logfields.Modification: modType,
			}).Warning("unable to update bpf map")
		}
	case ipcache.Delete:
		err := l.bpfMap.Delete(&key)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"key":                  key.String(),
				logfields.IPAddr:       cidr,
				logfields.Identity:     newID,
				logfields.Modification: modType,
			}).Warning("unable to delete from bpf map")
		}
	default:
		scopedLog.Warning("cache modification type not supported")
	}
}

// updateStaleEntriesFunction returns a DumpCallback that will update the
// specified "keysToRemove" map with entries that exist in the BPF map which
// do not exist in the in-memory ipcache.
//
// Must be called while holding l.ipcache.Lock for reading.
func (l *BPFListener) updateStaleEntriesFunction(keysToRemove map[string]*ipcacheMap.Key) bpf.DumpCallback {
	return func(key bpf.MapKey, _ bpf.MapValue) {
		k := key.(*ipcacheMap.Key)
		keyToIP := k.String()

		// Don't RLock as part of the same goroutine.
		if i, exists := l.ipcache.LookupByPrefixRLocked(keyToIP); !exists {
			switch i.Source {
			case source.KVStore, source.Local:
				// Cannot delete from map during callback because DumpWithCallback
				// RLocks the map.
				keysToRemove[keyToIP] = k.DeepCopy()
			}
		}
	}
}

// garbageCollect implements GC of the ipcache map in the following way:
//
//	Periodically sweep through every element in the BPF map and check it
//	against the in-memory copy of the map. If it doesn't exist in memory,
//	delete the entry.
//
// Returns an error if garbage collection failed to occur.
func (l *BPFListener) garbageCollect(ctx context.Context) (*sync.WaitGroup, error) {
	log.Debug("Running garbage collection for BPF IPCache")

	// Since controllers run asynchronously, need to make sure
	// IPIdentityCache is not being updated concurrently while we
	// do GC;
	l.ipcache.RLock()
	defer l.ipcache.RUnlock()

	keysToRemove := map[string]*ipcacheMap.Key{}
	if err := l.bpfMap.DumpWithCallback(l.updateStaleEntriesFunction(keysToRemove)); err != nil {
		return nil, fmt.Errorf("error dumping ipcache BPF map: %s", err)
	}

	// Remove all keys which are not in in-memory cache from BPF map
	// for consistency.
	for _, k := range keysToRemove {
		log.WithFields(logrus.Fields{logfields.BPFMapKey: k}).
			Debug("deleting from ipcache BPF map")
		if err := l.bpfMap.Delete(k); err != nil {
			return nil, fmt.Errorf("error deleting key %s from ipcache BPF map: %s", k, err)
		}
	}
	return nil, nil
}

// OnIPIdentityCacheGC spawns a controller which synchronizes the BPF IPCache Map
// with the in-memory IP-Identity cache.
func (l *BPFListener) OnIPIdentityCacheGC() {
	// This controller ensures that the in-memory IP-identity cache is in-sync
	// with the BPF map on disk. These can get out of sync if the cilium-agent
	// is offline for some time, as the maps persist on the BPF filesystem.
	// In the case that there is some loss of event history in the key-value
	// store (e.g., compaction in etcd), we cannot rely upon the key-value store
	// fully to give us the history of all events. As such, periodically check
	// for inconsistencies in the data-path with that in the agent to ensure
	// consistent state.
	l.ipcache.UpdateController("ipcache-bpf-garbage-collection",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				wg, err := l.garbageCollect(ctx)
				if err != nil {
					return err
				}
				if wg != nil {
					wg.Wait()
				}
				return nil
			},
			RunInterval: 5 * time.Minute,
		},
	)
}
