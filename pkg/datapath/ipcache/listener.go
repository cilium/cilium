// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipcache

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/node"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-ipcache")

type IPCacheListenerBPF struct {
	// regenerator allows this listener to trigger BPF program regeneration.
	regenerator regenerator

	// bpfMap is the BPF map that this listener will update when events are
	// received from the IPCache.
	bpfMap *ipcacheMap.Map

	// deleteNotifier will be closed after a delete operation is triggered.
	deleteNotifier chan bool

	// detectDeleteSupportOnce protects initialization of 'deleteSupported'.
	detectDeleteSupportOnce sync.Once

	// deleteSupported determines whether the kernel supports deleting
	// elements from the IPCache.
	deleteSupported bool
}

type regenerator interface {
	TriggerRegeneration(string) (*sync.WaitGroup, error)
}

func newListener(m *ipcacheMap.Map, r regenerator) *IPCacheListenerBPF {
	return &IPCacheListenerBPF{
		bpfMap:         m,
		regenerator:    r,
		deleteNotifier: make(chan bool),
	}
}

func NewListener(r regenerator) *IPCacheListenerBPF {
	return newListener(ipcacheMap.IPCache, r)
}

// OnIPIdentityCacheChange is called whenever there is a change of state in the
// IPCache (pkg/ipcache).
// TODO (FIXME): GH-3161.
//
// 'oldIPIDPair' is ignored here, because in the BPF maps an update for the
// IP->ID mapping will replace any existing contents; knowledge of the old pair
// is not required to upsert the new pair.
func (l *IPCacheListenerBPF) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr net.IPNet,
	oldHostIP, newHostIP net.IP, oldID *identity.NumericIdentity, newID identity.NumericIdentity) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       cidr,
		logfields.Identity:     newID,
		logfields.Modification: modType,
	})

	scopedLog.Debug("Daemon notified of IP-Identity cache state change")

	// TODO - see if we can factor this into an interface under something like
	// pkg/datapath instead of in the daemon directly so that the code is more
	// logically located.

	// Update BPF Maps.

	key := ipcacheMap.NewKey(cidr.IP, cidr.Mask)

	switch modType {
	case ipcache.Upsert:
		value := ipcacheMap.RemoteEndpointInfo{
			SecurityIdentity: uint32(newID),
		}

		if newHostIP != nil {
			// If the hostIP is specified and it doesn't point to
			// the local host, then the ipcache should be populated
			// with the hostIP so that this traffic can be guided
			// to a tunnel endpoint destination.
			externalIP := node.GetExternalIPv4()
			if ip4 := newHostIP.To4(); ip4 != nil && !ip4.Equal(externalIP) {
				copy(value.TunnelEndpoint[:], ip4)
			}
		}
		err := ipcacheMap.IPCache.Update(&key, &value)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{"key": key.String(),
				"value": value.String()}).
				Warning("unable to update bpf map")
		}
	case ipcache.Delete:
		err := ipcacheMap.Delete(&key)
		if err == nil {
			if _, open := <-l.deleteNotifier; open {
				close(l.deleteNotifier)
			}
		} else {
			scopedLog.WithError(err).WithFields(logrus.Fields{"key": key.String()}).
				Warning("unable to delete from bpf map")
		}
	default:
		scopedLog.Warning("cache modification type not supported")
	}
}

// updateStaleEntriesFunction returns a DumpCallback that will update the
// specified "keysToRemove" map with entries that exist in the BPF map which
// do not exist in the in-memory ipcache.
//
// Must be called while holding ipcache.IPIdentityCache.Lock for reading.
func updateStaleEntriesFunction(keysToRemove map[string]*ipcacheMap.Key) bpf.DumpCallback {
	return func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*ipcacheMap.Key)
		keyToIP := k.String()

		// Don't RLock as part of the same goroutine.
		if i, exists := ipcache.IPIdentityCache.LookupByPrefixRLocked(keyToIP); !exists {
			switch i.Source {
			case ipcache.FromKVStore, ipcache.FromAgentLocal:
				// Cannot delete from map during callback because DumpWithCallback
				// RLocks the map.
				keysToRemove[keyToIP] = k
			}
		}
	}
}

// gcByDelete determines whether garbage collection should be implemented by
// creating a brand new map, populating it with all of the IPCache entries,
// deleting the old map, and regenerating all BPF programs.
//
// Returns true if running on Linux versions that support LPM map type but do
// not support deleting elements from the map (typically 4.11 <= x <= 4.14).
func (l *IPCacheListenerBPF) gcByDelete() bool {
	l.detectDeleteSupportOnce.Do(func() {
		// XXX: If both channels are closed, but the "UnsupportedDeleteNotifier"
		//      channel is closed first, does it guarantee that path will be
		//      executed rather than the other path?
		switch {
		case <-ipcacheMap.UnsupportedDeleteNotifier():
			log.Debug("Sweeping IPCache via map delete due to missing LPM delete support in kernel")
			l.deleteSupported = false
		case <-l.deleteNotifier:
			log.Debug("Observed successful LPM delete operation, garbage-collecting via sweep")
			l.deleteSupported = true
		}
	})

	return !l.deleteSupported
}

func handleMapShuffleFailure(oldPath, standardPath string) {
	if err := os.Rename(oldPath, standardPath); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.BPFMapPath: standardPath,
		}).Warningf("Unable to recover during error renaming map paths")
	}
}

// shuffleMaps attempts to move 'realizedPath' to 'oldPath' and 'newPath' to
// 'realizedPath'. If an error occurs, attempts to return the maps back to
// their original paths.
func shuffleMaps(realizedPath, oldPath, pendingPath string) error {
	if err := os.Rename(realizedPath, oldPath); err != nil {
		return fmt.Errorf("Unable to rename %s to %s: %s", realizedPath, oldPath, err)
	}

	if err := os.Rename(pendingPath, realizedPath); err != nil {
		handleMapShuffleFailure(oldPath, realizedPath)
		return fmt.Errorf("Unable to rename %s to %s: %s", pendingPath, realizedPath, err)
	}

	return nil
}

func (l *IPCacheListenerBPF) garbageCollect() error {
	deleteMap := l.gcByDelete()

	// Since controllers run asynchronously, need to make sure
	// IPIdentityCache is not being updated concurrently while we do
	// GC;
	ipcache.IPIdentityCache.RLock()
	defer ipcache.IPIdentityCache.RUnlock()

	if deleteMap {
		// Populate the map at the new path
		pendingMapName := fmt.Sprintf("%s_pending", ipcacheMap.Name)
		pendingMap := ipcacheMap.NewMap(pendingMapName)
		pendingListener := newListener(pendingMap, l.regenerator)
		ipcache.IPIdentityCache.DumpToListenerLocked(pendingListener)

		// Move the maps around on the filesystem so that BPF reload
		// will pick up the new paths without requiring recompilation.
		standardMapPath := bpf.MapPath(ipcacheMap.Name)
		oldMapPath := bpf.MapPath(fmt.Sprintf("%s_old", ipcacheMap.Name))
		pendingMapPath := bpf.MapPath(pendingMapName)
		if err := shuffleMaps(standardMapPath, oldMapPath, pendingMapPath); err != nil {
			return err
		}

		wg, err := l.regenerator.TriggerRegeneration("datapath ipcache")
		if err != nil {
			handleMapShuffleFailure(oldMapPath, standardMapPath)
			return err
		}
		wg.Wait()

		if err := ipcacheMap.Reopen(); err != nil {
			log.WithError(err).Warning("Failed to reopen BPF ipcache map")
			return err
		}
		l.bpfMap = ipcacheMap.IPCache
		_ = os.RemoveAll(oldMapPath)
	} else {
		keysToRemove := map[string]*ipcacheMap.Key{}
		if err := ipcacheMap.IPCache.DumpWithCallback(updateStaleEntriesFunction(keysToRemove)); err != nil {
			return fmt.Errorf("error dumping ipcache BPF map: %s", err)
		}

		// Remove all keys which are not in in-memory cache from BPF map
		// for consistency.
		for _, k := range keysToRemove {
			log.WithFields(logrus.Fields{logfields.BPFMapKey: k}).
				Debug("deleting from ipcache BPF map")
			if err := ipcacheMap.Delete(k); err != nil {
				return fmt.Errorf("error deleting key %s from ipcache BPF map: %s", k, err)
			}
		}
	}
	return nil
}

// OnIPIdentityCacheGC spawns a controller which synchronizes the BPF IPCache Map
// with the in-memory IP-Identity cache.
func (l *IPCacheListenerBPF) OnIPIdentityCacheGC() {
	// This controller ensures that the in-memory IP-identity cache is in-sync
	// with the BPF map on disk. These can get out of sync if the cilium-agent
	// is offline for some time, as the maps persist on the BPF filesystem.
	// In the case that there is some loss of event history in the key-value
	// store (e.g., compaction in etcd), we cannot rely upon the key-value store
	// fully to give us the history of all events. As such, periodically check
	// for inconsistencies in the data-path with that in the agent to ensure
	// consistent state.
	controller.NewManager().UpdateController("ipcache-bpf-garbage-collection",
		controller.ControllerParams{
			DoFunc:      l.garbageCollect,
			RunInterval: time.Duration(5) * time.Minute,
		},
	)
}
