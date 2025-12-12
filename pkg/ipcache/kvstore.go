// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	storepkg "github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
)

type kvstoreClient interface {
	// IsEnabled returns true if KVStore support is enabled.
	IsEnabled() bool

	// UpdateIfDifferent updates a key if the value is different
	UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error)
	// Delete deletes a key. It does not return an error if the key does not exist.
	Delete(ctx context.Context, key string) error
}

// IPIdentitySynchronizer handles the synchronization of ipcache entries into the kvstore.
type IPIdentitySynchronizer struct {
	logger  *slog.Logger
	client  kvstoreClient
	tracker lock.Map[string, []byte]
}

func NewIPIdentitySynchronizer(logger *slog.Logger, client kvstore.Client) *IPIdentitySynchronizer {
	return &IPIdentitySynchronizer{logger: logger, client: client}
}

// UpsertParams provides a structured set of parameters for IPIdentitySynchronizer.Upsert.
type UpsertParams struct {
	IP                netip.Addr
	HostIP            netip.Addr
	ID                identity.NumericIdentity
	Key               uint8
	Metadata          string
	K8sNamespace      string
	K8sPodName        string
	K8sServiceAccount string
	NPM               types.NamedPortMap
}

// Upsert updates / inserts the provided IP->Identity mapping into the kvstore.
func (s *IPIdentitySynchronizer) Upsert(ctx context.Context, params *UpsertParams) error {
	// Sort named ports into a slice
	namedPorts := make([]identity.NamedPort, 0, len(params.NPM))
	for name, value := range params.NPM {
		namedPorts = append(namedPorts, identity.NamedPort{
			Name:     name,
			Port:     value.Port,
			Protocol: u8proto.U8proto(value.Proto).String(),
		})
	}
	sort.Slice(namedPorts, func(i, j int) bool {
		return namedPorts[i].Name < namedPorts[j].Name
	})

	ipKey := path.Join(IPIdentitiesPath, AddressSpace, params.IP.String())
	ipIDPair := identity.IPIdentityPair{
		IP:                params.IP.AsSlice(),
		ID:                params.ID,
		Metadata:          params.Metadata,
		HostIP:            params.HostIP.AsSlice(),
		Key:               params.Key,
		K8sNamespace:      params.K8sNamespace,
		K8sPodName:        params.K8sPodName,
		K8sServiceAccount: params.K8sServiceAccount,
		NamedPorts:        namedPorts,
	}

	marshaledIPIDPair, err := json.Marshal(ipIDPair)
	if err != nil {
		return err
	}

	s.logger.Debug(
		"Upserting IP->ID mapping to kvstore",
		logfields.IPAddr, ipIDPair.IP,
		logfields.Identity, ipIDPair.ID,
		logfields.Key, ipIDPair.Key,
		logfields.Modification, Upsert,
	)

	_, err = s.client.UpdateIfDifferent(ctx, ipKey, marshaledIPIDPair, true)
	if err == nil {
		s.tracker.Store(ipKey, marshaledIPIDPair)
	}
	return err
}

// Delete removes the IP->Identity mapping for the specified ip
// from the kvstore, which will subsequently trigger an event in
// NewIPIdentityWatcher().
func (s *IPIdentitySynchronizer) Delete(ctx context.Context, ip string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, ip)
	s.tracker.Delete(ipKey)
	return s.client.Delete(ctx, ipKey)
}

// IsEnabled returns true if the synchronization to the KVStore is enabled.
func (s *IPIdentitySynchronizer) IsEnabled() bool {
	return s.client.IsEnabled()
}

// LocalIPIdentityWatcher is an IPIdentityWatcher specialized to watch the
// entries corresponding to the local cluster.
type LocalIPIdentityWatcher struct {
	logger  *slog.Logger
	watcher *IPIdentityWatcher
	syncer  *IPIdentitySynchronizer
	client  kvstore.Client
}

func NewLocalIPIdentityWatcher(in struct {
	cell.In

	Logger      *slog.Logger
	JobGroup    job.Group
	ClusterInfo cmtypes.ClusterInfo
	Client      kvstore.Client
	Factory     storepkg.Factory

	IPCache *IPCache
	Syncer  *IPIdentitySynchronizer
},
) *LocalIPIdentityWatcher {
	watcher := &LocalIPIdentityWatcher{
		logger: in.Logger,
		watcher: NewIPIdentityWatcher(
			in.Logger, in.ClusterInfo.Name, in.IPCache,
			in.Factory, source.KVStore,
		),
		syncer: in.Syncer,
		client: in.Client,
	}

	if watcher.IsEnabled() {
		// Start watcher for endpoint IP --> identity mappings in key-value store.
		// this needs to be done *after* that the ipcache map has been recreated
		// by the IPCache lifecycle hook.
		in.JobGroup.Add(job.OneShot("watch", watcher.Watch))
	}

	return watcher
}

// Watch starts the watcher and blocks waiting for events, until the context is closed.
func (liw *LocalIPIdentityWatcher) Watch(ctx context.Context, _ cell.Health) error {
	liw.logger.Info("Starting IP identity watcher")
	liw.watcher.Watch(ctx, liw.client, WithSelfDeletionProtection(liw.syncer))
	return nil
}

// WaitForSync blocks until either the initial list of entries had been retrieved
// from the kvstore, or the given context is canceled. It returns immediately in
// CRD mode
func (liw *LocalIPIdentityWatcher) WaitForSync(ctx context.Context) error {
	if !liw.client.IsEnabled() {
		return nil
	}

	return liw.watcher.WaitForSync(ctx)
}

// IsEnabled returns true if the synchronization from the KVStore is enabled.
func (liw *LocalIPIdentityWatcher) IsEnabled() bool {
	return liw.client.IsEnabled()
}

// IPIdentityWatcher is a watcher that will notify when IP<->identity mappings
// change in the kvstore.
type IPIdentityWatcher struct {
	log     *slog.Logger
	store   storepkg.WatchStore
	ipcache IPCacher

	clusterName                string
	clusterID                  uint32
	source                     source.Source
	withSelfDeletionProtection bool
	validators                 []ipIdentityValidator

	// Set only when withSelfDeletionProtection is true
	syncer *IPIdentitySynchronizer

	started bool
	synced  chan struct{}
}

type IPCacher interface {
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (bool, error)
	Delete(IP string, source source.Source) (namedPortsChanged bool)
}

// NewIPIdentityWatcher creates a new IPIdentityWatcher for the given cluster.
func NewIPIdentityWatcher(
	logger *slog.Logger, clusterName string, ipc IPCacher, factory storepkg.Factory,
	source source.Source, opts ...storepkg.RWSOpt,
) *IPIdentityWatcher {
	watcher := IPIdentityWatcher{
		ipcache:     ipc,
		clusterName: clusterName,
		source:      source,
		synced:      make(chan struct{}),
		log:         logger.With(logfields.ClusterName, clusterName),
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
	selfDeletionProtection *IPIdentitySynchronizer
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
// keys if they are detected to have been deleted, based on the synchronizer
// parameter.
func WithSelfDeletionProtection(synchronizer *IPIdentitySynchronizer) IWOpt {
	return func(opts *iwOpts) {
		opts.selfDeletionProtection = synchronizer
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
		iw.log.Info(
			"ClusterID changed: draining all known ipcache entries",
			logfields.ClusterID, iwo.clusterID,
		)
		iw.store.Drain()
	}

	prefix := path.Join(IPIdentitiesPath, AddressSpace)
	if iwo.cachedPrefix {
		prefix = path.Join(kvstore.StateToCachePrefix(IPIdentitiesPath), iw.clusterName)
	}

	iw.started = true
	iw.clusterID = iwo.clusterID
	iw.withSelfDeletionProtection = iwo.selfDeletionProtection != nil
	iw.syncer = iwo.selfDeletionProtection
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

// WaitForSync blocks until either the initial list of entries had been retrieved
// from the kvstore, or the given context is canceled.
func (iw *IPIdentityWatcher) WaitForSync(ctx context.Context) error {
	select {
	case <-iw.synced:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
		iw.log.Warn("Ignoring entry with nil IP")
		return
	}

	iw.log.Debug(
		"Observed upsertion event",
		logfields.IPAddr, ip,
	)

	for _, validator := range iw.validators {
		if err := validator(ipIDPair); err != nil {
			iw.log.Warn(
				"Skipping invalid upsertion event",
				logfields.Error, err,
				logfields.IPAddr, ip,
			)
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
				iw.log.Error(
					"Parsing named port failed",
					logfields.Error, err,
					logfields.IPAddr, ipIDPair,
				)
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

	iw.log.Debug(
		"Observed deletion event",
		logfields.IPAddr, ip,
	)

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
	key := path.Join(IPIdentitiesPath, AddressSpace, ip)
	if m, ok := iw.syncer.tracker.Load(key); ok {
		iw.log.Warn(
			"Received kvstore delete notification for alive ipcache entry",
			logfields.IPAddr, ip,
		)
		_, err := iw.syncer.client.UpdateIfDifferent(context.TODO(), key, m, true)
		if err != nil {
			iw.log.Warn(
				"Unable to re-create alive ipcache entry",
				logfields.Error, err,
				logfields.IPAddr, ip,
			)
		}
		return true
	}

	return false
}
