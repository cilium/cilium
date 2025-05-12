// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"net"
	"path"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/version"
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "clustermesh",
		Short: "Run ClusterMesh",
		Run: func(cmd *cobra.Command, args []string) {
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "clustermesh-apiserver")
			if err := h.Run(logger); err != nil {
				logging.Fatal(logger, err.Error())
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for the ClusterMesh API Server
			metrics.Namespace = metrics.CiliumClusterMeshAPIServerNamespace
			option.Config.SetupLogging(h.Viper(), "clustermesh-apiserver")

			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "clustermesh-apiserver")

			option.Config.Populate(logger, h.Viper())
			option.LogRegisteredSlogOptions(h.Viper(), logger)
			logger.Info("Cilium ClusterMesh", logfields.Version, version.Version)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())
	return rootCmd
}

type parameters struct {
	cell.In

	CfgMCSAPI      operator.MCSAPIConfig
	ClusterInfo    cmtypes.ClusterInfo
	Clientset      k8sClient.Clientset
	Resources      cmk8s.Resources
	BackendPromise promise.Promise[kvstore.BackendOperations]
	StoreFactory   store.Factory
	SyncState      syncstate.SyncState
	CESConfig      cmk8s.CiliumEndpointSliceConfig

	Logger *slog.Logger
}

func registerHooks(lc cell.Lifecycle, params parameters) error {
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if !params.Clientset.IsEnabled() {
				return errors.New("Kubernetes client not configured, cannot continue.")
			}

			backend, err := params.BackendPromise.Await(ctx)
			if err != nil {
				return err
			}

			startServer(params.ClusterInfo, params.Clientset, backend, params.Resources, params.StoreFactory, params.SyncState, params.CfgMCSAPI.ClusterMeshEnableMCSAPI, params.Logger, params.CESConfig.EnableCiliumEndpointSlice)
			return nil
		},
	})
	return nil
}

type identitySynchronizer struct {
	store        store.SyncStore
	syncCallback func(context.Context)
	logger       *slog.Logger
}

func newIdentitySynchronizer(ctx context.Context, logger *slog.Logger, cinfo cmtypes.ClusterInfo, backend kvstore.BackendOperations, factory store.Factory, syncCallback func(context.Context)) synchronizer {
	identitiesStore := factory.NewSyncStore(cinfo.Name, backend,
		path.Join(identityCache.IdentitiesPath, "id"),
		store.WSSWithSyncedKeyOverride(identityCache.IdentitiesPath))
	go identitiesStore.Run(ctx)

	return &identitySynchronizer{store: identitiesStore, syncCallback: syncCallback, logger: logger}
}

func parseLabelArrayFromMap(base map[string]string) labels.LabelArray {
	array := make(labels.LabelArray, 0, len(base))
	for sourceAndKey, value := range base {
		array = append(array, labels.NewLabel(sourceAndKey, value, ""))
	}
	return array.Sort()
}

func (is *identitySynchronizer) upsert(ctx context.Context, _ resource.Key, obj runtime.Object) error {
	identity := obj.(*ciliumv2.CiliumIdentity)
	if len(identity.SecurityLabels) == 0 {
		is.logger.Warn(
			"Ignoring invalid identity",
			logfields.Error, errors.New("missing security labels"),
			logfields.Identity, identity.Name,
		)
		// Do not return an error, since it is pointless to retry.
		// We will receive a new update event if the security labels change.
		return nil
	}

	labelArray := parseLabelArrayFromMap(identity.SecurityLabels)

	var labels []byte
	for _, l := range labelArray {
		labels = append(labels, l.FormatForKVStore()...)
	}

	is.logger.Info("Upserting identity in etcd", logfields.Identity, identity.Name)
	kv := store.NewKVPair(identity.Name, string(labels))
	if err := is.store.UpsertKey(ctx, kv); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		is.logger.Warn("Unable to upsert identity in etcd", logfields.Error, err)
	}

	return nil
}

func (is *identitySynchronizer) delete(ctx context.Context, key resource.Key) error {
	is.logger.Info("Deleting identity from etcd", logfields.Identity, key.Name)

	if err := is.store.DeleteKey(ctx, store.NewKVPair(key.Name, "")); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		is.logger.Warn("Unable to delete node from etcd",
			logfields.Error, err,
			logfields.Identity, key.Name,
		)
	}

	return nil
}

func (is *identitySynchronizer) synced(ctx context.Context) error {
	is.logger.Info("Initial list of identities successfully received from Kubernetes")
	return is.store.Synced(ctx, is.syncCallback)
}

type nodeStub struct {
	cluster string
	name    string
}

func (n *nodeStub) GetKeyName() string {
	return nodeTypes.GetKeyNodeName(n.cluster, n.name)
}

type nodeSynchronizer struct {
	clusterInfo  cmtypes.ClusterInfo
	store        store.SyncStore
	syncCallback func(context.Context)
	logger       *slog.Logger
}

func newNodeSynchronizer(ctx context.Context, logger *slog.Logger, cinfo cmtypes.ClusterInfo, backend kvstore.BackendOperations, factory store.Factory, syncCallback func(context.Context)) synchronizer {
	nodesStore := factory.NewSyncStore(cinfo.Name, backend, nodeStore.NodeStorePrefix)
	go nodesStore.Run(ctx)

	return &nodeSynchronizer{clusterInfo: cinfo, store: nodesStore, syncCallback: syncCallback, logger: logger}
}

func (ns *nodeSynchronizer) upsert(ctx context.Context, _ resource.Key, obj runtime.Object) error {
	n := nodeTypes.ParseCiliumNode(obj.(*ciliumv2.CiliumNode))
	n.Cluster = ns.clusterInfo.Name
	n.ClusterID = ns.clusterInfo.ID

	ns.logger.Info("Upserting node in etcd", logfields.Node, n.Name)

	if err := ns.store.UpsertKey(ctx, &n); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		ns.logger.Warn("Unable to upsert node in etcd", logfields.Error, err)
	}

	return nil
}

func (ns *nodeSynchronizer) delete(ctx context.Context, key resource.Key) error {
	n := nodeStub{
		cluster: ns.clusterInfo.Name,
		name:    key.Name,
	}

	ns.logger.Info("Deleting node from etcd", logfields.Node, key.Name)

	if err := ns.store.DeleteKey(ctx, &n); err != nil {
		// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
		ns.logger.Warn("Unable to delete node from etcd",
			logfields.Error, err,
			logfields.Node, key.Name,
		)
	}

	return nil
}

func (ns *nodeSynchronizer) synced(ctx context.Context) error {
	ns.logger.Info("Initial list of nodes successfully received from Kubernetes")
	return ns.store.Synced(ctx, ns.syncCallback)
}

type ipmap map[string]struct{}

type endpointSynchronizer struct {
	store                     store.SyncStore
	cache                     map[string]ipmap
	syncCallback              func(context.Context)
	logger                    *slog.Logger
	enableCiliumEndpointSlice bool
}

func newEndpointSynchronizer(ctx context.Context, logger *slog.Logger, cinfo cmtypes.ClusterInfo, backend kvstore.BackendOperations, factory store.Factory, syncCallback func(context.Context), enableCiliumEndpointSlice bool) synchronizer {
	endpointsStore := factory.NewSyncStore(cinfo.Name, backend,
		path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace),
		store.WSSWithSyncedKeyOverride(ipcache.IPIdentitiesPath))
	go endpointsStore.Run(ctx)

	return &endpointSynchronizer{
		store:                     endpointsStore,
		cache:                     make(map[string]ipmap),
		syncCallback:              syncCallback,
		logger:                    logger,
		enableCiliumEndpointSlice: enableCiliumEndpointSlice,
	}
}

func (es *endpointSynchronizer) upsert(ctx context.Context, key resource.Key, obj runtime.Object) error {
	var epIter iter.Seq2[string, identity.IPIdentityPair]
	if es.enableCiliumEndpointSlice {
		epIter = es.cesIterator(obj)
	} else {
		epIter = es.cepIterator(obj)
	}
	es.upsertEndpoints(ctx, key, epIter)

	return nil
}

func (es *endpointSynchronizer) upsertEndpoints(ctx context.Context, key resource.Key, pairs iter.Seq2[string, identity.IPIdentityPair]) error {
	ips := make(ipmap)
	stale := es.cache[key.String()]

	log := es.logger.With(logfields.Endpoint, key)

	for ip, entry := range pairs {
		log.Info("Upserting endpoint in etcd", logfields.IPAddr, ip)
		if err := es.store.UpsertKey(ctx, &entry); err != nil {
			// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
			log.Warn("Unable to upsert endpoint in etcd",
				logfields.Error, err,
				logfields.IPAddr, ip,
			)
			continue
		}

		ips[ip] = struct{}{}
		delete(stale, ip)
	}

	// Delete the stale endpoint IPs from the KVStore.
	es.deleteEndpoints(ctx, key, stale)
	es.cache[key.String()] = ips

	return nil
}

func (es *endpointSynchronizer) cepIterator(obj runtime.Object) iter.Seq2[string, identity.IPIdentityPair] {
	return func(yield func(string, identity.IPIdentityPair) bool) {
		endpoint := obj.(*types.CiliumEndpoint)

		if n := endpoint.Networking; n != nil {
			for _, address := range n.Addressing {
				for _, ip := range []string{address.IPV4, address.IPV6} {
					if ip == "" {
						continue
					}
					entry := identity.IPIdentityPair{
						IP:           net.ParseIP(ip),
						HostIP:       net.ParseIP(n.NodeIP),
						K8sNamespace: endpoint.Namespace,
						K8sPodName:   endpoint.Name,
					}

					if endpoint.Identity != nil {
						entry.ID = identity.NumericIdentity(endpoint.Identity.ID)
					}

					if endpoint.Encryption != nil {
						entry.Key = uint8(endpoint.Encryption.Key)
					}

					if !yield(ip, entry) {
						return
					}
				}
			}
		}
	}
}

func (es *endpointSynchronizer) cesIterator(obj runtime.Object) iter.Seq2[string, identity.IPIdentityPair] {
	return func(yield func(string, identity.IPIdentityPair) bool) {
		endpointslice := obj.(*ciliumv2a1.CiliumEndpointSlice)

		for _, endpoint := range endpointslice.Endpoints {
			if n := endpoint.Networking; n != nil {
				for _, address := range n.Addressing {
					for _, ip := range []string{address.IPV4, address.IPV6} {
						if ip == "" {
							continue
						}

						entry := identity.IPIdentityPair{
							IP:           net.ParseIP(ip),
							HostIP:       net.ParseIP(n.NodeIP),
							K8sNamespace: endpointslice.Namespace,
							K8sPodName:   endpoint.Name,
							ID:           identity.NumericIdentity(endpoint.IdentityID),
							Key:          uint8(endpoint.Encryption.Key),
						}

						if !yield(ip, entry) {
							return
						}
					}
				}
			}
		}
	}
}

func (es *endpointSynchronizer) delete(ctx context.Context, key resource.Key) error {
	es.deleteEndpoints(ctx, key, es.cache[key.String()])
	delete(es.cache, key.String())
	return nil
}

func (es *endpointSynchronizer) synced(ctx context.Context) error {
	es.logger.Info("Initial list of endpoints successfully received from Kubernetes")
	return es.store.Synced(ctx, es.syncCallback)
}

func (es *endpointSynchronizer) deleteEndpoints(ctx context.Context, key resource.Key, ips ipmap) {
	log := es.logger.With(logfields.Endpoint, key)
	for ip := range ips {
		log.Info("Deleting endpoint from etcd", logfields.IPAddr, ip)

		entry := identity.IPIdentityPair{IP: net.ParseIP(ip)}
		if err := es.store.DeleteKey(ctx, &entry); err != nil {
			// The only errors surfaced by WorkqueueSyncStore are the unrecoverable ones.
			log.Warn("Unable to delete endpoint from etcd",
				logfields.Error, err,
				logfields.IPAddr, ip,
			)
		}
	}
}

type synchronizer interface {
	upsert(ctx context.Context, key resource.Key, obj runtime.Object) error
	delete(ctx context.Context, key resource.Key) error
	synced(ctx context.Context) error
}

func synchronize[T runtime.Object](ctx context.Context, r resource.Resource[T], sync synchronizer) {
	for event := range r.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			event.Done(sync.upsert(ctx, event.Key, event.Object))
		case resource.Delete:
			event.Done(sync.delete(ctx, event.Key))
		case resource.Sync:
			event.Done(sync.synced(ctx))
		}
	}
}

func startServer(
	cinfo cmtypes.ClusterInfo,
	clientset k8sClient.Clientset,
	backend kvstore.BackendOperations,
	resources cmk8s.Resources,
	factory store.Factory,
	syncState syncstate.SyncState,
	clusterMeshEnableMCSAPI bool,
	logger *slog.Logger,
	enableCiliumEndpointSlice bool,
) {
	logger.Info(
		"Starting clustermesh-apiserver...",
		logfields.ClusterName, cinfo.Name,
		logfields.ClusterID, cinfo.ID,
	)

	config := cmtypes.CiliumClusterConfig{
		ID: cinfo.ID,
		Capabilities: cmtypes.CiliumClusterConfigCapabilities{
			SyncedCanaries:        true,
			MaxConnectedClusters:  cinfo.MaxConnectedClusters,
			ServiceExportsEnabled: &clusterMeshEnableMCSAPI,
		},
	}

	_, err := cmutils.EnforceClusterConfig(context.Background(), cinfo.Name, config, backend, logger)
	if err != nil {
		logging.Fatal(logger, "Unable to set local cluster config on kvstore", logfields.Error, err)
	}

	ctx := context.Background()
	go synchronize(ctx, resources.CiliumIdentities, newIdentitySynchronizer(ctx, logger, cinfo, backend, factory, syncState.WaitForResource()))
	go synchronize(ctx, resources.CiliumNodes, newNodeSynchronizer(ctx, logger, cinfo, backend, factory, syncState.WaitForResource()))

	if enableCiliumEndpointSlice {
		logger.Info("Synchronizing endpoints using CiliumEndpointSlices")
		go synchronize(ctx, resources.CiliumEndpointSlices, newEndpointSynchronizer(ctx, logger, cinfo, backend, factory, syncState.WaitForResource(), enableCiliumEndpointSlice))
	} else {
		logger.Info("Synchronizing endpoints using CiliumEndpoints")
		go synchronize(ctx, resources.CiliumSlimEndpoints, newEndpointSynchronizer(ctx, logger, cinfo, backend, factory, syncState.WaitForResource(), enableCiliumEndpointSlice))
	}

	operatorWatchers.StartSynchronizingServices(ctx, &sync.WaitGroup{}, operatorWatchers.ServiceSyncParameters{
		ClusterInfo:  cinfo,
		Clientset:    clientset,
		Services:     resources.Services,
		Endpoints:    resources.Endpoints,
		Backend:      backend,
		StoreFactory: factory,
		SyncCallback: syncState.WaitForResource(),
	}, logger)
	go mcsapi.StartSynchronizingServiceExports(ctx, mcsapi.ServiceExportSyncParameters{
		Logger:                  logger,
		ClusterName:             cinfo.Name,
		ClusterMeshEnableMCSAPI: clusterMeshEnableMCSAPI,
		Clientset:               clientset,
		ServiceExports:          resources.ServiceExports,
		Services:                resources.Services,
		Backend:                 backend,
		StoreFactory:            factory,
		SyncCallback:            syncState.WaitForResource(),
	})
	syncState.Stop()

	logger.Info("Initialization complete")
}
