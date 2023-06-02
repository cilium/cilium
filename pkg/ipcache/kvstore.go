// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// DefaultAddressSpace is the address space used if none is provided.
	// TODO - once pkg/node adds this to clusterConfiguration, remove.
	DefaultAddressSpace = "default"
)

var (
	// IPIdentitiesPath is the path to where endpoint IPs are stored in the key-value
	// store.
	IPIdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "ip", "v1")

	// AddressSpace is the address space (cluster, etc.) in which policy is
	// computed. It is determined by the orchestration system / runtime.
	AddressSpace = DefaultAddressSpace

	// globalMap wraps the kvstore and provides a cache of all entries
	// which are owned by a local user
	globalMap = newKVReferenceCounter(kvstoreImplementation{})

	setupIPIdentityWatcher sync.Once
)

// store is a key-value store for an underlying implementation, provided to
// mock out the kvstore for unit testing.
type store interface {
	// update will insert the {key, value} tuple into the underlying
	// kvstore.
	upsert(ctx context.Context, key string, value string, lease bool) error

	// delete will remove the key from the underlying kvstore.
	release(ctx context.Context, key string) error
}

// kvstoreImplementation is a store implementation backed by the kvstore.
type kvstoreImplementation struct{}

// upsert places the mapping of {key, value} into the kvstore, optionally with
// a lease.
func (k kvstoreImplementation) upsert(ctx context.Context, key string, value string, lease bool) error {
	_, err := kvstore.Client().UpdateIfDifferent(ctx, key, []byte(value), lease)
	return err
}

// release removes the specified key from the kvstore.
func (k kvstoreImplementation) release(ctx context.Context, key string) error {
	return kvstore.Client().Delete(ctx, key)
}

// kvReferenceCounter provides a thin wrapper around the kvstore which adds
// reference tracking for all entries which are used by a local user.
type kvReferenceCounter struct {
	lock.Mutex
	store

	// marshaledIPIDPair is map indexed by the key that contains the
	// marshaled IPIdentityPair
	marshaledIPIDPairs map[string][]byte
}

// newKVReferenceCounter creates a new reference counter using the specified
// store as the underlying location for key/value pairs to be stored.
func newKVReferenceCounter(s store) *kvReferenceCounter {
	return &kvReferenceCounter{
		store:              s,
		marshaledIPIDPairs: map[string][]byte{},
	}
}

// UpsertIPToKVStore updates / inserts the provided IP->Identity mapping into the
// kvstore, which will subsequently trigger an event in NewIPIdentityWatcher().
func UpsertIPToKVStore(ctx context.Context, IP, hostIP netip.Addr, ID identity.NumericIdentity, key uint8,
	metadata, k8sNamespace, k8sPodName string, npm types.NamedPortMap) error {
	// Sort named ports into a slice
	namedPorts := make([]identity.NamedPort, 0, len(npm))
	for name, value := range npm {
		namedPorts = append(namedPorts, identity.NamedPort{
			Name:     name,
			Port:     value.Port,
			Protocol: u8proto.U8proto(value.Proto).String(),
		})
	}
	sort.Slice(namedPorts, func(i, j int) bool {
		return namedPorts[i].Name < namedPorts[j].Name
	})

	ipKey := path.Join(IPIdentitiesPath, AddressSpace, IP.String())
	ipIDPair := identity.IPIdentityPair{
		IP:           IP.AsSlice(),
		ID:           ID,
		Metadata:     metadata,
		HostIP:       hostIP.AsSlice(),
		Key:          key,
		K8sNamespace: k8sNamespace,
		K8sPodName:   k8sPodName,
		NamedPorts:   namedPorts,
	}

	marshaledIPIDPair, err := json.Marshal(ipIDPair)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.IPAddr:       ipIDPair.IP,
		logfields.Identity:     ipIDPair.ID,
		logfields.Key:          ipIDPair.Key,
		logfields.Modification: Upsert,
	}).Debug("Upserting IP->ID mapping to kvstore")

	err = globalMap.store.upsert(ctx, ipKey, string(marshaledIPIDPair), true)
	if err == nil {
		globalMap.Lock()
		globalMap.marshaledIPIDPairs[ipKey] = marshaledIPIDPair
		globalMap.Unlock()
	}
	return err
}

// keyToIPNet returns the IPNet describing the key, whether it is a host, and
// an error (if one occurs)
func keyToIPNet(key string) (parsedPrefix *net.IPNet, host bool, err error) {
	requiredPrefix := fmt.Sprintf("%s/", path.Join(IPIdentitiesPath, AddressSpace))
	if !strings.HasPrefix(key, requiredPrefix) {
		err = fmt.Errorf("found invalid key %s outside of prefix %s", key, IPIdentitiesPath)
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
func DeleteIPFromKVStore(ctx context.Context, ip string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, ip)
	globalMap.Lock()
	delete(globalMap.marshaledIPIDPairs, ipKey)
	globalMap.Unlock()
	return globalMap.store.release(ctx, ipKey)
}

// IPIdentityWatcher is a watcher that will notify when IP<->identity mappings
// change in the kvstore
type IPIdentityWatcher struct {
	backend    kvstore.BackendOperations
	stop       chan struct{}
	synced     chan struct{}
	stopOnce   sync.Once
	syncedOnce sync.Once

	clusterID uint32

	ipcache IPCacher
}

type IPCacher interface {
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (bool, error)
	ForEachListener(f func(listener IPIdentityMappingListener))
	Delete(IP string, source source.Source) (namedPortsChanged bool)
}

// NewIPIdentityWatcher creates a new IPIdentityWatcher using the specified
// kvstore backend.
func NewIPIdentityWatcher(ipc IPCacher, backend kvstore.BackendOperations) *IPIdentityWatcher {
	return NewClusterIPIdentityWatcher(0, ipc, backend)
}

// NewClusterIPIdentityWatcher creates a new IPIdentityWatcher using the specified
// kvstore backend. The difference between the watcher created by NewIPIdentityWatcher
// is that each IP <=> Identity mapping will be annotated with ClusterID. Thus, it
// can be used for watching the kvstore of the remote cluster with overlapping PodCIDR.
// Calling this function with clusterID = 0 is identical to calling NewIPIdentityWatcher.
func NewClusterIPIdentityWatcher(clusterID uint32, ipc IPCacher, backend kvstore.BackendOperations) *IPIdentityWatcher {
	watcher := &IPIdentityWatcher{
		clusterID: clusterID,
		backend:   backend,
		stop:      make(chan struct{}),
		synced:    make(chan struct{}),
		ipcache:   ipc,
	}
	return watcher
}

// Watch starts the watcher and blocks waiting for events. When events are
// received from the kvstore, All IPIdentityMappingListener are notified. The
// function returns when IPIdentityWatcher.Close() is called. The watcher will
// automatically restart as required.
func (iw *IPIdentityWatcher) Watch(ctx context.Context) {

	scopedLog := log

restart:
	watcher := iw.backend.ListAndWatch(ctx, "endpointIPWatcher", IPIdentitiesPath, 512)

	for {
		select {
		// Get events from channel as they come in.
		case event, ok := <-watcher.Events:
			if !ok {
				log.Debugf("%s closed, restarting watch", watcher.String())
				time.Sleep(500 * time.Millisecond)
				goto restart
			}

			if option.Config.Debug {
				scopedLog = log.WithFields(logrus.Fields{
					"kvstore-event": event.Typ.String(),
					"key":           event.Key,
				})
				scopedLog.Debug("Received event")
			}

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
				iw.ipcache.ForEachListener(func(listener IPIdentityMappingListener) {
					listener.OnIPIdentityCacheGC()
				})
				iw.closeSynced()

			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				var ipIDPair identity.IPIdentityPair
				err := json.Unmarshal(event.Value, &ipIDPair)
				if err != nil {
					log.WithFields(logrus.Fields{
						"kvstore-event": event.Typ.String(),
						"key":           event.Key,
					}).WithError(err).Error("Not adding entry to ip cache; error unmarshaling data from key-value store")
					continue
				}
				ip := ipIDPair.PrefixString()
				if ip == "<nil>" {
					if option.Config.Debug {
						scopedLog.Debug("Ignoring entry with nil IP")
					}
					continue
				}
				var k8sMeta *K8sMetadata
				if ipIDPair.K8sNamespace != "" || ipIDPair.K8sPodName != "" || len(ipIDPair.NamedPorts) > 0 {
					k8sMeta = &K8sMetadata{
						Namespace:  ipIDPair.K8sNamespace,
						PodName:    ipIDPair.K8sPodName,
						NamedPorts: make(types.NamedPortMap, len(ipIDPair.NamedPorts)),
					}
					for _, np := range ipIDPair.NamedPorts {
						err = k8sMeta.NamedPorts.AddPort(np.Name, int(np.Port), np.Protocol)
						if err != nil {
							log.WithFields(logrus.Fields{
								"kvstore-event": event.Typ.String(),
								"key":           event.Key,
							}).WithError(err).Error("Parsing named port failed")
						}
					}
				}

				peerIdentity := ipIDPair.ID
				if option.Config.EnableRemoteNodeIdentity && peerIdentity == identity.ReservedIdentityHost {
					// The only way we can discover IPs associated with the local host
					// is directly via the NodeDiscovery package. If someone is informing
					// this agent about IPs corresponding to the "host" via the kvstore,
					// then they're sharing their own perspective on their own node IPs'
					// identity. However, this node has remote-node enabled, so we should
					// treat the peer as a "remote-node", not a "host".
					peerIdentity = identity.ReservedIdentityRemoteNode
				}

				if iw.clusterID != 0 {
					// Annotate IP/Prefix string with ClusterID. So that we can distinguish
					// the two network endpoints that have the same IP adddress, but belogs
					// to the different clusters.
					ip = cmtypes.AnnotateIPCacheKeyWithClusterID(ip, iw.clusterID)
				}

				// There is no need to delete the "old" IP addresses from this
				// ip ID pair. The only places where the ip ID pair are created
				// is the clustermesh, where it sends a delete to the KVStore,
				// and the endpoint-runIPIdentitySync where it bounded to a
				// lease and a controller which is stopped/removed when the
				// endpoint is gone.
				iw.ipcache.Upsert(ip, ipIDPair.HostIP, ipIDPair.Key, k8sMeta, Identity{
					ID:     peerIdentity,
					Source: source.KVStore,
				})

			case kvstore.EventTypeDelete:
				// Value is not present in deletion event;
				// need to convert kvstore key to IP.
				ipnet, isHost, err := keyToIPNet(event.Key)
				if err != nil {
					log.WithFields(logrus.Fields{
						"kvstore-event": event.Typ.String(),
						"key":           event.Key,
					}).WithError(err).Error("Error parsing IP from key")
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
					err := globalMap.store.upsert(ctx, event.Key, string(m), true)
					if err != nil {
						log.WithError(err).WithField("ip", ip).Warning("Unable to re-create alive ipcache entry")
					}
					globalMap.Unlock()
				} else {
					globalMap.Unlock()

					if iw.clusterID != 0 {
						// See equivalent logic in the kvstore.EventTypeUpdate case
						ip = cmtypes.AnnotateIPCacheKeyWithClusterID(ip, iw.clusterID)
					}

					// The key no longer exists in the
					// local cache, it is safe to remove
					// from the datapath ipcache.
					iw.ipcache.Delete(ip, source.KVStore)
				}
			}
		case <-ctx.Done():
			// Stop this identity watcher, we have been signaled to shut down
			// via context. This will result in iw.stop being closed.
			iw.Close()
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

// closeSynced the IPIdentityWathcer and case panic
func (iw *IPIdentityWatcher) closeSynced() {
	iw.syncedOnce.Do(func() {
		close(iw.synced)
	})
}

func (iw *IPIdentityWatcher) waitForInitialSync() {
	<-iw.synced
}

var (
	watcher     *IPIdentityWatcher
	initialized = make(chan struct{})
)

// InitIPIdentityWatcher initializes the watcher for ip-identity mapping events
// in the key-value store.
func (ipc *IPCache) InitIPIdentityWatcher(ctx context.Context) {
	setupIPIdentityWatcher.Do(func() {
		go func() {
			log.Info("Starting IP identity watcher")
			watcher = NewIPIdentityWatcher(ipc, kvstore.Client())
			close(initialized)
			watcher.Watch(ctx)
		}()
	})
}

// WaitForKVStoreSync waits until the ipcache has been synchronized from the kvstore
func WaitForKVStoreSync() {
	<-initialized
	watcher.waitForInitialSync()
}
