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
	"sync"

	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	storepkg "github.com/cilium/cilium/pkg/kvstore/store"
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
// change in the kvstore.
type IPIdentityWatcher struct {
	store   storepkg.WatchStore
	ipcache IPCacher

	clusterName                string
	clusterID                  uint32
	source                     source.Source
	withSelfDeletionProtection bool
	validators                 []ipIdentityValidator

	started bool
	synced  chan struct{}
	log     *logrus.Entry
}

type IPCacher interface {
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (bool, error)
	Delete(IP string, source source.Source) (namedPortsChanged bool)
}

// NewIPIdentityWatcher creates a new IPIdentityWatcher for the given cluster.
func NewIPIdentityWatcher(
	clusterName string, ipc IPCacher, factory storepkg.Factory,
	source source.Source, opts ...storepkg.RWSOpt,
) *IPIdentityWatcher {
	watcher := IPIdentityWatcher{
		ipcache:     ipc,
		clusterName: clusterName,
		source:      source,
		synced:      make(chan struct{}),
		log:         log.WithField(logfields.ClusterName, clusterName),
	}

	watcher.store = factory.NewWatchStore(
		clusterName,
		func() storepkg.Key { return &identity.IPIdentityPair{} },
		&watcher,
		append(opts, storepkg.RWSWithOnSyncCallback(watcher.onSync))...,
	)
	return &watcher
}

type ipIdentityValidator func(*identity.IPIdentityPair) error
type IWOpt func(*iwOpts)

type iwOpts struct {
	clusterID              uint32
	selfDeletionProtection bool
	cachedPrefix           bool
	validators             []ipIdentityValidator
}

// WithClusterID configures the ClusterID associated with the given watcher.
func WithClusterID(id uint32) IWOpt {
	return func(opts *iwOpts) {
		opts.clusterID = id
	}
}

// WithSelfDeletionProtection enables the automatic re-creation of the owned
// keys if they are detected to have been deleted. Note that this operation
// is performed using the client provided by kvstore.Client(), and shall not
// be enabled when using a different client.
func WithSelfDeletionProtection() IWOpt {
	return func(opts *iwOpts) {
		opts.selfDeletionProtection = true
	}
}

// WithCachedPrefix adapts the watched prefix based on the fact that the information
// concerning the given cluster is cached from an external kvstore.
func WithCachedPrefix(cached bool) IWOpt {
	return func(opts *iwOpts) {
		opts.cachedPrefix = cached
	}
}

// WithIdentityValidator registers a validation function to ensure that the
// observed IPs are associated with an identity belonging to the expected range.
func WithIdentityValidator(clusterID uint32) IWOpt {
	return func(opts *iwOpts) {
		min := identity.GetMinimalAllocationIdentity(clusterID)
		max := identity.GetMaximumAllocationIdentity(clusterID)

		validator := func(pair *identity.IPIdentityPair) error {
			switch {
			// The identity belongs to the expected range based on the Cluster ID.
			case pair.ID >= min && pair.ID <= max:
				return nil

			// Allow all reserved IDs as well, including well-known and
			// user-reserved identities, as they are not scoped by Cluster ID.
			case pair.ID < identity.MinimalNumericIdentity:
				return nil

			default:
				return fmt.Errorf("ID %d does not belong to the allocation range of cluster ID %d", pair.ID, clusterID)
			}
		}

		opts.validators = append(opts.validators, validator)
	}
}

// Watch starts the watcher and blocks waiting for events, until the context is
// closed. When events are received from the kvstore, all IPIdentityMappingListener
// are notified. It automatically emits deletion events for stale keys when appropriate
// (that is, when the watcher is restarted, and if the ClusterID is changed).
func (iw *IPIdentityWatcher) Watch(ctx context.Context, backend storepkg.WatchStoreBackend, opts ...IWOpt) {
	var iwo iwOpts
	for _, opt := range opts {
		opt(&iwo)
	}

	if iw.started && iw.clusterID != iwo.clusterID {
		iw.log.WithField(logfields.ClusterID, iwo.clusterID).
			Info("ClusterID changed: draining all known ipcache entries")
		iw.store.Drain()
	}

	prefix := path.Join(IPIdentitiesPath, AddressSpace)
	if iwo.cachedPrefix {
		prefix = path.Join(kvstore.StateToCachePrefix(IPIdentitiesPath), iw.clusterName)
	}

	iw.started = true
	iw.clusterID = iwo.clusterID
	iw.withSelfDeletionProtection = iwo.selfDeletionProtection
	iw.validators = iwo.validators
	iw.store.Watch(ctx, backend, prefix)
}

// Drain triggers a deletion event for all known ipcache entries.
func (iw *IPIdentityWatcher) Drain() {
	iw.store.Drain()
}

// NumEntries returns the number of entries synchronized from the kvstore.
func (iw *IPIdentityWatcher) NumEntries() uint64 {
	return iw.store.NumEntries()
}

// Synced returns whether the initial list of entries has been retrieved from
// the kvstore, and new events are currently being watched.
func (iw *IPIdentityWatcher) Synced() bool {
	return iw.store.Synced()
}

// OnUpdate is triggered when a new upsertion event is observed, and
// synchronizes local caching of endpoint IP to ipIDPair mapping with
// the operation the key-value store has informed us about.
//
// To resolve conflicts between hosts and full CIDR prefixes:
//   - Insert hosts into the cache as ".../w.x.y.z"
//   - Insert CIDRS into the cache as ".../w.x.y.z/N"
//   - If a host entry created, notify the listeners.
//   - If a CIDR is created and there's no overlapping host
//     entry, ie it is a less than fully masked CIDR, OR
//     it is a fully masked CIDR and there is no corresponding
//     host entry, then:
//   - Notify the listeners.
//   - Otherwise, do not notify listeners.
func (iw *IPIdentityWatcher) OnUpdate(k storepkg.Key) {
	ipIDPair := k.(*identity.IPIdentityPair)

	ip := ipIDPair.PrefixString()
	if ip == "<nil>" {
		iw.log.Debug("Ignoring entry with nil IP")
		return
	}

	iw.log.WithField(logfields.IPAddr, ip).Debug("Observed upsertion event")

	for _, validator := range iw.validators {
		if err := validator(ipIDPair); err != nil {
			log.WithError(err).WithField(logfields.IPAddr, ip).
				Warning("Skipping invalid upsertion event")
			return
		}
	}

	var k8sMeta *K8sMetadata
	if ipIDPair.K8sNamespace != "" || ipIDPair.K8sPodName != "" || len(ipIDPair.NamedPorts) > 0 {
		k8sMeta = &K8sMetadata{
			Namespace:  ipIDPair.K8sNamespace,
			PodName:    ipIDPair.K8sPodName,
			NamedPorts: make(types.NamedPortMap, len(ipIDPair.NamedPorts)),
		}
		for _, np := range ipIDPair.NamedPorts {
			err := k8sMeta.NamedPorts.AddPort(np.Name, int(np.Port), np.Protocol)
			if err != nil {
				iw.log.WithFields(logrus.Fields{
					logfields.IPAddr: ipIDPair,
				}).WithError(err).Error("Parsing named port failed")
			}
		}
	}

	peerIdentity := ipIDPair.ID
	if peerIdentity == identity.ReservedIdentityHost {
		// The only way we can discover IPs associated with the local host
		// is directly via the NodeDiscovery package. If someone is informing
		// this agent about IPs corresponding to the "host" via the kvstore,
		// then they're sharing their own perspective on their own node IPs'
		// identity. We should treat the peer as a "remote-node", not a "host".
		peerIdentity = identity.ReservedIdentityRemoteNode
	}

	if iw.clusterID != 0 {
		// Annotate IP/Prefix string with ClusterID. So that we can distinguish
		// the two network endpoints that have the same IP adddress, but belongs
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
		Source: iw.source,
	})
}

// OnDelete is triggered when a new deletion event is observed, and
// synchronizes local caching of endpoint IP to ipIDPair mapping with
// the operation the key-value store has informed us about.
//
// To resolve conflicts between hosts and full CIDR prefixes:
//   - If a host is removed, check for an overlapping CIDR
//     and if it exists, notify the listeners with an upsert
//     for the CIDR's identity
//   - If any other deletion case, notify listeners of
//     the deletion event.
func (iw *IPIdentityWatcher) OnDelete(k storepkg.NamedKey) {
	ipIDPair := k.(*identity.IPIdentityPair)
	ip := ipIDPair.PrefixString()

	iw.log.WithField(logfields.IPAddr, ip).Debug("Observed deletion event")

	if iw.withSelfDeletionProtection && iw.selfDeletionProtection(ip) {
		return
	}

	if iw.clusterID != 0 {
		// See equivalent logic in the kvstore.EventTypeUpdate case
		ip = cmtypes.AnnotateIPCacheKeyWithClusterID(ip, iw.clusterID)
	}

	// The key no longer exists in the
	// local cache, it is safe to remove
	// from the datapath ipcache.
	iw.ipcache.Delete(ip, iw.source)
}

func (iw *IPIdentityWatcher) onSync(context.Context) {
	close(iw.synced)
}

func (iw *IPIdentityWatcher) selfDeletionProtection(ip string) bool {
	globalMap.Lock()
	defer globalMap.Unlock()

	key := path.Join(IPIdentitiesPath, AddressSpace, ip)
	if m, ok := globalMap.marshaledIPIDPairs[key]; ok {
		iw.log.WithField(logfields.IPAddr, ip).Warning("Received kvstore delete notification for alive ipcache entry")
		err := globalMap.store.upsert(context.TODO(), key, string(m), true)
		if err != nil {
			iw.log.WithError(err).WithField(logfields.IPAddr, ip).Warning("Unable to re-create alive ipcache entry")
		}
		return true
	}

	return false
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
func (ipc *IPCache) InitIPIdentityWatcher(ctx context.Context, factory storepkg.Factory) {
	setupIPIdentityWatcher.Do(func() {
		go func() {
			log.Info("Starting IP identity watcher")
			watcher = NewIPIdentityWatcher(option.Config.ClusterName, ipc, factory, source.KVStore)
			close(initialized)
			watcher.Watch(ctx, kvstore.Client(), WithSelfDeletionProtection())
		}()
	})
}

// WaitForKVStoreSync waits until the ipcache has been synchronized from the kvstore
func WaitForKVStoreSync() {
	<-initialized
	watcher.waitForInitialSync()
}
