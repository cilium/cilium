// Copyright 2016-2019 Authors of Cilium
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
	"context"
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

// datapath is an interface to the datapath implementation, used to apply
// changes that are made within this module.
type datapath interface {
	TriggerReloadWithoutCompile(reason string) (*sync.WaitGroup, error)
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
}

func newListener(m *ipcacheMap.Map, d datapath) *BPFListener {
	return &BPFListener{
		bpfMap:   m,
		datapath: d,
	}
}

// NewListener returns a new listener to push IPCache entries into BPF maps.
func NewListener(d datapath) *BPFListener {
	return newListener(ipcacheMap.IPCache, d)
}

// OnIPIdentityCacheChange is called whenever there is a change of state in the
// IPCache (pkg/ipcache).
// TODO (FIXME): GH-3161.
//
// 'oldIPIDPair' is ignored here, because in the BPF maps an update for the
// IP->ID mapping will replace any existing contents; knowledge of the old pair
// is not required to upsert the new pair.
func (l *BPFListener) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr net.IPNet,
	oldHostIP, newHostIP net.IP, oldID *identity.NumericIdentity, newID identity.NumericIdentity, encryptKey uint8) {
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
			Key:              encryptKey,
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
		err := l.bpfMap.Update(&key, &value)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{"key": key.String(),
				"value": value.String()}).
				Warning("unable to update bpf map")
		}
	case ipcache.Delete:
		err := l.bpfMap.Delete(&key)
		if err != nil {
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
	return func(key bpf.MapKey, _ bpf.MapValue) {
		k := key.(*ipcacheMap.Key)
		keyToIP := k.String()

		// Don't RLock as part of the same goroutine.
		if i, exists := ipcache.IPIdentityCache.LookupByPrefixRLocked(keyToIP); !exists {
			switch i.Source {
			case ipcache.FromKVStore, ipcache.FromAgentLocal:
				// Cannot delete from map during callback because DumpWithCallback
				// RLocks the map.
				keysToRemove[keyToIP] = k.DeepCopy()
			}
		}
	}
}

// handleMapShuffleFailure attempts to move the map with name 'backup' back to
// 'realized', and logs a warning message if this can't be achieved.
func handleMapShuffleFailure(src, dst string) {
	backupPath := bpf.MapPath(src)
	realizedPath := bpf.MapPath(dst)

	if err := os.Rename(backupPath, realizedPath); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.BPFMapPath: realizedPath,
		}).Warningf("Unable to recover during error renaming map paths")
	}
}

// shuffleMaps attempts to move the map with name 'realized' to 'backup' and
// 'pending' to 'realized'. If an error occurs, attempts to return the maps
// back to their original paths.
func shuffleMaps(realized, backup, pending string) error {
	realizedPath := bpf.MapPath(realized)
	backupPath := bpf.MapPath(backup)
	pendingPath := bpf.MapPath(pending)

	if err := os.Rename(realizedPath, backupPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("Unable to back up existing ipcache: %s", err)
	}

	if err := os.Rename(pendingPath, realizedPath); err != nil {
		handleMapShuffleFailure(backup, realized)
		return fmt.Errorf("Unable to shift ipcache into new location: %s", err)
	}

	return nil
}

// garbageCollect implements GC of the ipcache map in one of two ways:
//
// On Linux 4.9, 4.10 or 4.15 and later:
//   Periodically sweep through every element in the BPF map and check it
//   against the in-memory copy of the map. If it doesn't exist in memory,
//   delete the entry.
// On Linux 4.11 to 4.14:
//   Create a brand new map, populate it with all of the IPCache entries from
//   the in-memory cache, delete the old map, and trigger regeneration of all
//   BPF programs so that they pick up the new map.
//
// Returns an error if garbage collection failed to occur.
func (l *BPFListener) garbageCollect(ctx context.Context) error {
	log.Debug("Running garbage collection for BPF IPCache")

	// Since controllers run asynchronously, need to make sure
	// IPIdentityCache is not being updated concurrently while we do
	// GC;
	ipcache.IPIdentityCache.RLock()
	defer ipcache.IPIdentityCache.RUnlock()

	if ipcacheMap.SupportsDelete() {
		keysToRemove := map[string]*ipcacheMap.Key{}
		if err := l.bpfMap.DumpWithCallback(updateStaleEntriesFunction(keysToRemove)); err != nil {
			return fmt.Errorf("error dumping ipcache BPF map: %s", err)
		}

		// Remove all keys which are not in in-memory cache from BPF map
		// for consistency.
		for _, k := range keysToRemove {
			log.WithFields(logrus.Fields{logfields.BPFMapKey: k}).
				Debug("deleting from ipcache BPF map")
			if err := l.bpfMap.Delete(k); err != nil {
				return fmt.Errorf("error deleting key %s from ipcache BPF map: %s", k, err)
			}
		}
	} else {
		// Populate the map at the new path
		pendingMapName := fmt.Sprintf("%s_pending", ipcacheMap.Name)
		pendingMap := ipcacheMap.NewMap(pendingMapName)
		if _, err := pendingMap.OpenOrCreate(); err != nil {
			return fmt.Errorf("Unable to create %s map: %s", pendingMapName, err)
		}
		pendingListener := newListener(pendingMap, l.datapath)
		ipcache.IPIdentityCache.DumpToListenerLocked(pendingListener)
		err := pendingMap.Close()
		if err != nil {
			log.WithError(err).WithField("map-name", pendingMapName).Warning("unable to close map")
		}

		// Move the maps around on the filesystem so that BPF reload
		// will pick up the new paths without requiring recompilation.
		backupMapName := fmt.Sprintf("%s_old", ipcacheMap.Name)
		if err := shuffleMaps(ipcacheMap.Name, backupMapName, pendingMapName); err != nil {
			return err
		}

		wg, err := l.datapath.TriggerReloadWithoutCompile("datapath ipcache")
		if err != nil {
			handleMapShuffleFailure(backupMapName, ipcacheMap.Name)
			return err
		}

		// If the base programs successfully compiled, then the maps
		// should be OK so let's update all references to the IPCache
		// so that they point to the new version.
		_ = os.RemoveAll(bpf.MapPath(backupMapName))
		if err := ipcacheMap.Reopen(); err != nil {
			// Very unlikely; base program compilation succeeded.
			log.WithError(err).Warning("Failed to reopen BPF ipcache map")
			return err
		}
		wg.Wait()
	}
	return nil
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
	controller.NewManager().UpdateController("ipcache-bpf-garbage-collection",
		controller.ControllerParams{
			DoFunc:      l.garbageCollect,
			RunInterval: 5 * time.Minute,
		},
	)
}
