// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type authMapGarbageCollector struct {
	logger          *slog.Logger
	authmap         authMap
	nodeIDHandler   node.IDHandler
	authTypeFetcher authTypeFetcher
	db              *statedb.DB
	nodes           statedb.Table[*node.Node]

	ciliumNodesMutex   lock.Mutex
	ciliumNodesSynced  bool
	ciliumNodesChanged bool
	activeNodeIDs      map[uint16]struct{}
	activeNodeIDsReady bool

	ciliumIdentitiesMutex      lock.RWMutex
	ciliumIdentitiesDiscovered map[identity.NumericIdentity]struct{}
	ciliumIdentitiesSynced     bool
	ciliumIdentitiesDeleted    map[identity.NumericIdentity]struct{}

	endpointsCache       map[uint16]*endpoint.Endpoint
	endpointsCacheSynced bool
	endpointsCacheMutex  lock.RWMutex
}

// authTypeFetcher returns the AuthTypes required by the policy between two
// identities. Today this is satisfied by the policy compute cell.
type authTypeFetcher interface {
	GetAuthTypes(localID, remoteID identity.NumericIdentity) policyTypes.AuthTypes
}

func newAuthMapGC(
	logger *slog.Logger,
	authmap authMap,
	nodeIDHandler node.IDHandler,
	authTypeFetcher authTypeFetcher,
	db *statedb.DB,
	nodes statedb.Table[*node.Node],
) *authMapGarbageCollector {
	return &authMapGarbageCollector{
		logger:          logger,
		authmap:         authmap,
		nodeIDHandler:   nodeIDHandler,
		authTypeFetcher: authTypeFetcher,
		db:              db,
		nodes:           nodes,

		ciliumIdentitiesDiscovered: map[identity.NumericIdentity]struct{}{},
		ciliumIdentitiesDeleted:    map[identity.NumericIdentity]struct{}{},
	}
}

func (r *authMapGarbageCollector) cleanup(ctx context.Context) error {
	if err := r.cleanupExpiredEntries(ctx); err != nil {
		return err
	}

	if err := r.cleanupNodes(ctx); err != nil {
		return err
	}

	if err := r.cleanupEndpoints(ctx); err != nil {
		return err
	}

	if err := r.cleanupIdentities(ctx); err != nil {
		return err
	}

	if err := r.cleanupEntriesWithoutAuthPolicy(ctx); err != nil {
		return err
	}

	return nil
}

// Nodes

func (r *authMapGarbageCollector) observeNodeChanges(ctx context.Context) error {
	_, initialized := r.nodes.Initialized(r.db.ReadTxn())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-initialized:
	}

	nodeSet, activeNodeIDs, activeNodeIDsReady, watch := r.nodeStateWatch()
	r.ciliumNodesMutex.Lock()
	r.logger.Debug("Nodes synced")
	r.ciliumNodesSynced = true
	r.ciliumNodesChanged = true
	r.activeNodeIDs = activeNodeIDs
	r.activeNodeIDsReady = activeNodeIDsReady
	r.ciliumNodesMutex.Unlock()

	// Coalesce bursts of node updates before comparing the current node set.
	limiter := rate.NewLimiter(50*time.Millisecond, 1)
	defer limiter.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		newNodeSet, newActiveNodeIDs, newActiveNodeIDsReady, newWatch := r.nodeStateWatch()
		watch = newWatch
		if maps.Equal(nodeSet, newNodeSet) {
			if !activeNodeIDsReady && newActiveNodeIDsReady {
				activeNodeIDs = newActiveNodeIDs
				activeNodeIDsReady = true
				r.ciliumNodesMutex.Lock()
				r.activeNodeIDs = activeNodeIDs
				r.activeNodeIDsReady = true
				r.ciliumNodesMutex.Unlock()
			}
			continue
		}
		nodeSet = newNodeSet
		activeNodeIDs = newActiveNodeIDs
		activeNodeIDsReady = newActiveNodeIDsReady
		r.ciliumNodesMutex.Lock()
		r.ciliumNodesChanged = true
		r.activeNodeIDs = activeNodeIDs
		r.activeNodeIDsReady = activeNodeIDsReady
		r.ciliumNodesMutex.Unlock()
	}
}

func (r *authMapGarbageCollector) nodeStateWatch() (
	map[nodeTypes.Identity]struct{},
	map[uint16]struct{},
	bool,
	<-chan struct{},
) {
	nodes, watch := r.nodes.AllWatch(r.db.ReadTxn())
	nodeSet := map[nodeTypes.Identity]struct{}{}
	activeNodeIDs := map[uint16]struct{}{0: {}} // Local node 0 is always available.
	activeNodeIDsReady := true
	for n := range nodes {
		nodeSet[n.Identity()] = struct{}{}
		if n.IsLocal() {
			continue
		}
		for _, addr := range n.IPAddresses {
			if addr.Type != addressing.NodeInternalIP {
				continue
			}
			nodeID, exists := r.nodeIDHandler.GetNodeID(ip.AddrFromIP(addr.IP))
			if !exists {
				activeNodeIDsReady = false
				continue
			}
			activeNodeIDs[nodeID] = struct{}{}
		}
	}
	return nodeSet, activeNodeIDs, activeNodeIDsReady, watch
}

func (r *authMapGarbageCollector) cleanupNodes(_ context.Context) error {
	r.ciliumNodesMutex.Lock()
	defer r.ciliumNodesMutex.Unlock()

	r.logger.Debug("Cleaning up entries which belong to deleted nodes")

	if !r.ciliumNodesSynced {
		r.logger.Debug("Skipping nodes cleanup - not synced yet")
		return nil
	}
	if !r.ciliumNodesChanged {
		return nil
	}

	if !r.activeNodeIDsReady {
		_, r.activeNodeIDs, r.activeNodeIDsReady, _ = r.nodeStateWatch()
		if !r.activeNodeIDsReady {
			r.logger.Debug("Node IDs not ready, deferring auth map cleanup")
			return nil
		}
	}

	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if _, ok := r.activeNodeIDs[key.remoteNodeID]; !ok {
			r.logger.Debug("Deleting entry due to removed remote node", logfields.RemoteNodeID, key.remoteNodeID)
			return true
		}
		return false
	})

	if err != nil {
		return fmt.Errorf("failed to cleanup missing nodes: %w", err)
	}

	r.ciliumNodesChanged = false
	return nil
}

// Identities

func (r *authMapGarbageCollector) handleIdentityChange(_ context.Context, e cache.IdentityChange) (err error) {
	r.ciliumIdentitiesMutex.Lock()
	defer r.ciliumIdentitiesMutex.Unlock()

	switch e.Kind {
	case cache.IdentityChangeUpsert:
		// Upsert events need to be caputured as long as the first GC run uses them
		// and resets ciliumIdentitiesDiscovered to nil
		if r.ciliumIdentitiesDiscovered != nil {
			r.logger.Debug("Identity discovered - mark to keep",
				logfields.Identity, e.ID,
				logfields.Labels, e.Labels)
			r.ciliumIdentitiesDiscovered[e.ID] = struct{}{}
		}
	case cache.IdentityChangeSync:
		r.logger.Debug("Identities synced")
		r.ciliumIdentitiesSynced = true
	case cache.IdentityChangeDelete:
		r.logger.Debug("Identity deleted - mark for deletion",
			logfields.Identity, e.ID,
			logfields.Labels, e.Labels)
		r.ciliumIdentitiesDeleted[e.ID] = struct{}{}
	}
	return nil
}

func (r *authMapGarbageCollector) cleanupIdentities(_ context.Context) error {
	r.ciliumIdentitiesMutex.Lock()
	defer r.ciliumIdentitiesMutex.Unlock()

	r.logger.Debug("Cleaning up entries which belong to deleted identities")

	if !r.ciliumIdentitiesSynced {
		r.logger.Debug("Skipping identities cleanup - not synced yet")
		return nil
	}

	if err := r.cleanupMissingIdentities(); err != nil {
		return fmt.Errorf("failed to cleanup missing identities: %w", err)
	}

	if err := r.cleanupDeletedIdentities(); err != nil {
		return fmt.Errorf("failed to cleanup deleted identities: %w", err)
	}

	return nil
}

func (r *authMapGarbageCollector) cleanupMissingIdentities() error {
	if r.ciliumIdentitiesDiscovered == nil {
		return nil
	}

	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if _, ok := r.ciliumIdentitiesDiscovered[key.localIdentity]; !ok {
			r.logger.Debug("Deleting entry due to removed local identity", logfields.LocalIdentity, key.localIdentity)
			return true
		}
		if _, ok := r.ciliumIdentitiesDiscovered[key.remoteIdentity]; !ok {
			r.logger.Debug("Deleting entry due to removed remote identity", logfields.RemoteIdentity, key.remoteIdentity)
			return true
		}
		return false
	})

	if err != nil {
		return err
	}

	r.ciliumIdentitiesDiscovered = nil

	return nil
}

func (r *authMapGarbageCollector) cleanupDeletedIdentities() error {
	for id := range r.ciliumIdentitiesDeleted {
		if err := r.cleanupDeletedIdentity(id); err != nil {
			// keep entry and try to delete it during the next gc execution
			return fmt.Errorf("failed to cleanup deleted identity: %w", err)
		}
		delete(r.ciliumIdentitiesDeleted, id)
	}

	return nil
}

func (r *authMapGarbageCollector) cleanupDeletedIdentity(id identity.NumericIdentity) error {
	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if key.localIdentity == id || key.remoteIdentity == id {
			r.logger.Debug("Deleting entry due to removed identity", logfields.Identity, id)
			return true
		}
		return false
	})
}

// Policies

func (r *authMapGarbageCollector) cleanupEntriesWithoutAuthPolicy(_ context.Context) error {
	r.logger.Debug("Cleaning up entries which no longer require authentication by a policy")

	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		authTypes := r.authTypeFetcher.GetAuthTypes(key.localIdentity, key.remoteIdentity)

		if _, ok := authTypes[key.authType]; !ok {
			r.logger.Debug("Deleting entry because no policy requires authentication",
				logfields.Key, key,
				logfields.AuthType, key.authType,
			)
			return true
		}
		return false
	})

	if err != nil {
		return fmt.Errorf("failed to cleanup entries without any auth policy: %w", err)
	}
	return nil
}

// Expired

func (r *authMapGarbageCollector) cleanupExpiredEntries(_ context.Context) error {
	now := time.Now()
	r.logger.Debug("Cleaning up expired entries", logfields.GCTime, now)
	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if info.expiration.Before(now) {
			r.logger.Debug("Deleting entry due to expiration",
				logfields.GCTime, now,
				logfields.Expiration, info.expiration,
			)
			return true
		}
		return false
	})

	if err != nil {
		return fmt.Errorf("failed to cleanup expired entries: %w", err)
	}
	return nil
}

// Endpoints

func (r *authMapGarbageCollector) subscribeToEndpointEvents(endpointManager endpointmanager.EndpointManager) {
	localEPs := endpointManager.GetEndpoints()

	r.endpointsCacheMutex.Lock()
	r.endpointsCache = map[uint16]*endpoint.Endpoint{}
	for _, ep := range localEPs {
		r.endpointsCache[ep.GetID16()] = ep
	}
	r.endpointsCacheSynced = true
	r.endpointsCacheMutex.Unlock()

	endpointManager.Subscribe(r)
}

func (r *authMapGarbageCollector) EndpointCreated(ep *endpoint.Endpoint) {
	r.endpointsCacheMutex.Lock()
	r.endpointsCache[ep.GetID16()] = ep
	r.endpointsCacheMutex.Unlock()
}

func (r *authMapGarbageCollector) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	r.endpointsCacheMutex.Lock()
	delete(r.endpointsCache, ep.GetID16())
	r.endpointsCacheMutex.Unlock()

	// when an endpoint got removed clean the authmap entries
	if err := r.cleanupEndpoints(context.Background()); err != nil {
		r.logger.Warn("failed to cleanup auth map entries related to endpoint entries", logfields.Error, err)
	}
}

// EndpointRestored implements endpointmanager.Subscriber.
func (r *authMapGarbageCollector) EndpointRestored(ep *endpoint.Endpoint) {
	// No-op
}

func (r *authMapGarbageCollector) cleanupEndpoints(_ context.Context) error {
	r.ciliumIdentitiesMutex.RLock()
	if r.ciliumIdentitiesDiscovered == nil || !r.ciliumIdentitiesSynced || !r.endpointsCacheSynced {
		r.ciliumIdentitiesMutex.RUnlock()
		return nil
	}
	r.ciliumIdentitiesMutex.RUnlock()

	r.endpointsCacheMutex.RLock()
	idsInUse := map[identity.NumericIdentity]struct{}{}
	for _, ep := range r.endpointsCache {
		if id, err := ep.GetSecurityIdentity(); err == nil && id != nil {
			idsInUse[id.ID] = struct{}{}
		}
	}
	r.endpointsCacheMutex.RUnlock()
	r.ciliumIdentitiesMutex.RLock()
	defer r.ciliumIdentitiesMutex.RUnlock()
	for id := range r.ciliumIdentitiesDiscovered {
		if _, exists := idsInUse[id]; !exists {
			if err := r.cleanupDeletedEndpointIdentity(id); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *authMapGarbageCollector) cleanupDeletedEndpointIdentity(id identity.NumericIdentity) error {
	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if key.localIdentity == id || (key.remoteNodeID == 0 && key.remoteIdentity == id) {
			r.logger.Debug("Deleting identity entry due to removed endpoint", logfields.Identity, id)
			return true
		}
		return false
	})
}
