// Copyright 2018 Authors of Cilium
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
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultAddressSpace is the address space used if none is provided.
	// TODO - once pkg/node adds this to clusterConfiguration, remove.
	DefaultAddressSpace = "default"
)

var (
	// IPIdentitiesPath is the path to where endpoint IPs are stored in the key-value
	//store.
	IPIdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "ip", "v1")

	// AddressSpace is the address space (cluster, etc.) in which policy is
	// computed. It is determined by the orchestration system / runtime.
	AddressSpace = DefaultAddressSpace

	// globalMap wraps the kvstore and provides reference-tracking for keys
	// that are upserted or released from the kvstore.
	globalMap *kvReferenceCounter

	setupIPIdentityWatcher sync.Once
)

// store is a key-value store for an underlying implementation, provided to
// mock out the kvstore for unit testing.
type store interface {
	// update will insert the {key, value} tuple into the underlying
	// kvstore.
	upsert(key string, value []byte, lease bool) error

	// delete will remove the key from the underlying kvstore.
	release(key string) error
}

// kvstoreImplementation is a store implementation backed by the kvstore.
type kvstoreImplementation struct{}

// upsert places the mapping of {key, value} into the kvstore, optionally with
// a lease.
func (k kvstoreImplementation) upsert(key string, value []byte, lease bool) error {
	return kvstore.Update(key, value, lease)
}

// release removes the specified key from the kvstore.
func (k kvstoreImplementation) release(key string) error {
	return kvstore.Delete(key)
}

// kvReferenceCounter provides a thin wrapper around the kvstore which adds
// reference tracking for all entries being updated. When the first key is
// updated, it adds a reference to the kvstore and tracks the reference
// internally. Subsequent updates also update the kvstore, and add a reference.
// Deletes from the kvReferenceCounter are only propagated to the kvstore when
// the final reference is released.
//
// This has some small overlap with the pkg/kvstore/allocator but this is only
// a map from key to reference count rather than also tracking values.
type kvReferenceCounter struct {
	lock.Mutex
	store

	// keys is a map from key to reference count for locally-referenced
	// keys in the global kvstore.
	keys map[string]uint64

	// marshaledIPIDPair is map indexed by the key that contains the
	// marshaled IPIdentityPair
	marshaledIPIDPairs map[string][]byte
}

// newKVReferenceCounter creates a new reference counter using the specified
// store as the underlying location for key/value pairs to be stored.
func newKVReferenceCounter(s store) *kvReferenceCounter {
	return &kvReferenceCounter{
		store:              s,
		keys:               map[string]uint64{},
		marshaledIPIDPairs: map[string][]byte{},
	}
}

// upsert attempts to insert the specified {key, ipIDPair} into the kvstore. If
// the key has previously been upserted, increments a reference on the key.
// Always updates the underlying store with this {key, ipIDPair} tuple.
// Only adds a reference to the key if the upsert is successful.
func (r *kvReferenceCounter) upsert(ipKey string, ipIDPair identity.IPIdentityPair) error {
	marshaledIPIDPair, err := json.Marshal(ipIDPair)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.IPAddr:       ipIDPair.IP,
		logfields.IPMask:       ipIDPair.Mask,
		logfields.Identity:     ipIDPair.ID,
		logfields.Modification: Upsert,
	}).Debug("upserting CIDR->ID mapping to kvstore")

	r.Lock()
	defer r.Unlock()
	refcnt := r.keys[ipKey] // 0 if not found
	refcnt++
	err = r.store.upsert(ipKey, marshaledIPIDPair, true)
	if err == nil {
		r.keys[ipKey] = refcnt
		r.marshaledIPIDPairs[ipKey] = marshaledIPIDPair
	}
	return err
}

// release removes a reference to the specified key. If the number of
// references reaches 0, the key is removed from the underlying kvstore.
func (r *kvReferenceCounter) release(key string) (err error) {
	r.Lock()
	defer r.Unlock()

	refcnt, ok := r.keys[key] // 0 if not found
	// avoid underflow and report bug
	if !ok || refcnt == 0 {
		log.WithField("key", key).Error("BUG: attempt to release ipcache entry while refcnt == 0")
		return nil
	}

	refcnt--
	if refcnt == 0 {
		delete(r.keys, key)
		delete(r.marshaledIPIDPairs, key)
		err = r.store.release(key)
	} else {
		r.keys[key] = refcnt
	}
	return err
}

// UpsertIPToKVStore updates / inserts the provided IP->Identity mapping into the
// kvstore, which will subsequently trigger an event in NewIPIdentityWatcher().
func UpsertIPToKVStore(IP, hostIP net.IP, ID identity.NumericIdentity, metadata string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, IP.String())
	ipIDPair := identity.IPIdentityPair{
		IP:       IP,
		ID:       ID,
		Metadata: metadata,
		HostIP:   hostIP,
	}

	marshaledIPIDPair, err := json.Marshal(ipIDPair)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.IPAddr:       ipIDPair.IP,
		logfields.Identity:     ipIDPair.ID,
		logfields.Modification: Upsert,
	}).Debug("upserting IP->ID mapping to kvstore")

	return globalMap.store.upsert(ipKey, marshaledIPIDPair, true)
}

// keyToIPNet returns the IPNet describing the key, whether it is a host, and
// an error (if one occurs)
func keyToIPNet(key string) (parsedPrefix *net.IPNet, host bool, err error) {
	requiredPrefix := fmt.Sprintf("%s/", path.Join(IPIdentitiesPath, AddressSpace))
	if !strings.HasPrefix(key, requiredPrefix) {
		err = fmt.Errorf("Found invalid key %s outside of prefix %s", key, IPIdentitiesPath)
		return
	}

	suffix := strings.TrimPrefix(key, requiredPrefix)

	// Key is formatted as "prefix/192.0.2.0/24" for CIDRs
	_, parsedPrefix, err = net.ParseCIDR(suffix)
	if err != nil {
		// Key is likely a host in the format "prefix/192.0.2.3"
		parsedIP := net.ParseIP(suffix)
		if parsedIP == nil {
			err = fmt.Errorf("unable to parse IP from suffix %s", suffix)
			return
		}
		err = nil
		host = true
		ipv4 := parsedIP.To4()
		bits := net.IPv6len * 8
		if ipv4 != nil {
			parsedIP = ipv4
			bits = net.IPv4len * 8
		}
		parsedPrefix = &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(bits, bits)}
	}

	return
}

// DeleteIPFromKVStore removes the IP->Identity mapping for the specified ip
// from the kvstore, which will subsequently trigger an event in
// NewIPIdentityWatcher().
func DeleteIPFromKVStore(ip string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, ip)
	return globalMap.store.release(ipKey)
}

// IPIdentityWatcher is a watcher that will notify when IP<->identity mappings
// change in the kvstore
type IPIdentityWatcher struct {
	backend  kvstore.BackendOperations
	stop     chan struct{}
	stopOnce sync.Once
}

// NewIPIdentityWatcher creates a new IPIdentityWatcher using the specified
// kvstore backend
func NewIPIdentityWatcher(backend kvstore.BackendOperations) *IPIdentityWatcher {
	watcher := &IPIdentityWatcher{
		backend: backend,
		stop:    make(chan struct{}),
	}

	return watcher
}

// Watch starts the watcher and blocks waiting for events. When events are
// received from the kvstore, All IPIdentityMappingListener are notified. The
// function returns when IPIdentityWatcher.Close() is called. The watcher will
// automatically restart as required.
func (iw *IPIdentityWatcher) Watch() {
restart:
	watcher := iw.backend.ListAndWatch("endpointIPWatcher", IPIdentitiesPath, 512)

	for {
		select {
		// Get events from channel as they come in.
		case event, ok := <-watcher.Events:
			if !ok {
				log.Debugf("%s closed, restarting watch", watcher.String())
				time.Sleep(500 * time.Millisecond)
				goto restart
			}

			scopedLog := log.WithFields(logrus.Fields{"kvstore-event": event.Typ.String(), "key": event.Key})
			scopedLog.Debug("Received event")

			// Synchronize local caching of endpoint IP to ipIDPair mapping with
			// operation key-value store has informed us about.
			//
			// To resolve conflicts between hosts and full CIDR prefixes:
			// - Insert hosts into the cache as ".../w.x.y.z"
			// - Insert CIDRS into the cache as ".../w.x.y.z/N"
			// - If a host entry created, notify the listeners.
			// - If a CIDR is created and there's no overlapping host
			//   entry, ie it is a less than fully masked CIDR, OR
			//   it is a fully masked CIDR and there is no corresponding
			//   host entry, then:
			//   - Notify the listeners.
			//   - Otherwise, do not notify listeners.
			// - If a host is removed, check for an overlapping CIDR
			//   and if it exists, notify the listeners with an upsert
			//   for the CIDR's identity
			// - If any other deletion case, notify listeners of
			//   the deletion event.
			switch event.Typ {
			case kvstore.EventTypeListDone:
				IPIdentityCache.Lock()
				for _, listener := range IPIdentityCache.listeners {
					listener.OnIPIdentityCacheGC()
				}
				IPIdentityCache.Unlock()

			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				var ipIDPair identity.IPIdentityPair
				err := json.Unmarshal(event.Value, &ipIDPair)
				if err != nil {
					scopedLog.WithError(err).Errorf("Not adding entry to ip cache; error unmarshaling data from key-value store")
					continue
				}
				ip := ipIDPair.PrefixString()
				if ip == "<nil>" {
					scopedLog.Debug("Ignoring entry with nil IP")
					continue
				}

				IPIdentityCache.Upsert(ipIDPair.PrefixString(), ipIDPair.HostIP, Identity{
					ID:     ipIDPair.ID,
					Source: FromKVStore,
				})

			case kvstore.EventTypeDelete:
				// Value is not present in deletion event;
				// need to convert kvstore key to IP.
				ipnet, isHost, err := keyToIPNet(event.Key)
				if err != nil {
					scopedLog.WithError(err).Error("Error parsing IP from key")
					continue
				}
				var ip string
				if isHost {
					ip = ipnet.IP.String()
				} else {
					ip = ipnet.String()
				}
				globalMap.Lock()

				if m, ok := globalMap.marshaledIPIDPairs[event.Key]; ok {
					log.WithField("ip", ip).Warning("Received kvstore delete notification for alive ipcache entry")
					err := globalMap.store.upsert(event.Key, m, true)
					if err != nil {
						log.WithError(err).WithField("ip", ip).Warning("Unable to re-create alive ipcache entry")
					}
					globalMap.Unlock()
				} else {
					globalMap.Unlock()

					// The key no longer exists in the
					// local cache, it is safe to remove
					// from the datapath ipcache.
					IPIdentityCache.Delete(ip, FromKVStore)
				}
			}

		case <-iw.stop:
			// identity watcher was stopped
			watcher.Stop()
			return
		}
	}
}

// Close stops the IPIdentityWatcher and causes Watch() to return
func (iw *IPIdentityWatcher) Close() {
	iw.stopOnce.Do(func() {
		close(iw.stop)
	})
}

// InitIPIdentityWatcher initializes the watcher for ip-identity mapping events
// in the key-value store.
func InitIPIdentityWatcher() {
	setupIPIdentityWatcher.Do(func() {
		globalMap = newKVReferenceCounter(kvstoreImplementation{})
		go func() {
			log.Info("Starting IP identity watcher")
			watch := NewIPIdentityWatcher(kvstore.Client())
			watch.Watch()
		}()
	})
}
