// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"fmt"
	"log/slog"

	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
)

type authMapGarbageCollector struct {
	logger        *slog.Logger
	authmap       authMap
	nodeIDHandler datapathTypes.NodeIDHandler
	policyRepo    policyRepository

	ciliumNodesMutex      lock.Mutex
	ciliumNodesDiscovered map[uint16]struct{}
	ciliumNodesSynced     bool
	ciliumNodesDeleted    map[uint16]struct{}

	ciliumIdentitiesMutex      lock.RWMutex
	ciliumIdentitiesDiscovered map[identity.NumericIdentity]struct{}
	ciliumIdentitiesSynced     bool
	ciliumIdentitiesDeleted    map[identity.NumericIdentity]struct{}

	endpointsCache       map[uint16]*endpoint.Endpoint
	endpointsCacheSynced bool
	endpointsCacheMutex  lock.RWMutex
}

func (r *authMapGarbageCollector) Name() string {
	return "authmap-gc"
}

type policyRepository interface {
	GetAuthTypes(localID, remoteID identity.NumericIdentity) policyTypes.AuthTypes
}

func newAuthMapGC(logger *slog.Logger, authmap authMap, nodeIDHandler datapathTypes.NodeIDHandler, policyRepo policyRepository) *authMapGarbageCollector {
	return &authMapGarbageCollector{
		logger:        logger,
		authmap:       authmap,
		nodeIDHandler: nodeIDHandler,
		policyRepo:    policyRepo,

		ciliumNodesDiscovered: map[uint16]struct{}{
			0: {}, // Local node 0 is always available
		},
		ciliumNodesDeleted:         map[uint16]struct{}{},
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

func (r *authMapGarbageCollector) subscribeToNodeEvents(nodeManager manager.NodeManager) {
	nodeManager.Subscribe(r)

	r.logger.Debug("Nodes synced")
	r.ciliumNodesSynced = true
}

func (r *authMapGarbageCollector) NodeAdd(newNode nodeTypes.Node) error {
	r.ciliumNodesMutex.Lock()
	defer r.ciliumNodesMutex.Unlock()

	if r.ciliumNodesDiscovered != nil {
		remoteNodeIDs := r.remoteNodeIDs(newNode)
		r.logger.Debug("Node discovered - mark to keep",
			logfields.Name, newNode.Identity().Name,
			logfields.ClusterName, newNode.Identity().Cluster,
			logfields.NodeIDs, remoteNodeIDs,
		)
		for _, rID := range remoteNodeIDs {
			r.ciliumNodesDiscovered[rID] = struct{}{}
		}
	}

	return nil
}

func (r *authMapGarbageCollector) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	return nil
}

func (r *authMapGarbageCollector) NodeDelete(deletedNode nodeTypes.Node) error {
	r.ciliumNodesMutex.Lock()
	defer r.ciliumNodesMutex.Unlock()

	remoteNodeIDs := r.remoteNodeIDs(deletedNode)
	r.logger.Debug("Node deleted - mark for deletion",
		logfields.Name, deletedNode.Identity().Name,
		logfields.ClusterName, deletedNode.Identity().Cluster,
		logfields.NodeIDs, remoteNodeIDs,
	)
	for _, rID := range remoteNodeIDs {
		r.ciliumNodesDeleted[rID] = struct{}{}
	}

	return nil
}

func (r *authMapGarbageCollector) AllNodeValidateImplementation() {
}

func (r *authMapGarbageCollector) NodeValidateImplementation(node nodeTypes.Node) error {
	return nil
}

func (r *authMapGarbageCollector) NodeConfigurationChanged(config datapathTypes.LocalNodeConfiguration) error {
	return nil
}

func (r *authMapGarbageCollector) cleanupNodes(_ context.Context) error {
	r.ciliumNodesMutex.Lock()
	defer r.ciliumNodesMutex.Unlock()

	r.logger.Debug("Cleaning up entries which belong to deleted nodes")

	if !r.ciliumNodesSynced {
		r.logger.Debug("Skipping nodes cleanup - not synced yet")
		return nil
	}

	if err := r.cleanupMissingNodes(); err != nil {
		return fmt.Errorf("failed to cleanup missing nodes: %w", err)
	}

	if err := r.cleanupDeletedNodes(); err != nil {
		return fmt.Errorf("failed to cleanup deleted nodes: %w", err)
	}

	return nil
}

func (r *authMapGarbageCollector) cleanupDeletedNodes() error {
	for nodeID := range r.ciliumNodesDeleted {
		if err := r.cleanupDeletedNode(nodeID); err != nil {
			// keep entry and try to delete it during the next gc execution
			return fmt.Errorf("failed to cleanup deleted node: %w", err)
		}
		delete(r.ciliumNodesDeleted, nodeID)
	}

	return nil
}

func (r *authMapGarbageCollector) cleanupMissingNodes() error {
	if r.ciliumNodesDiscovered == nil {
		return nil
	}

	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if _, ok := r.ciliumNodesDiscovered[key.remoteNodeID]; !ok {
			r.logger.Debug("Deleting entry due to removed remote node", logfields.RemoteNodeID, key.remoteNodeID)
			return true
		}
		return false
	})

	if err != nil {
		return err
	}

	r.ciliumNodesDiscovered = nil

	return err
}

func (r *authMapGarbageCollector) cleanupDeletedNode(nodeID uint16) error {
	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if key.remoteNodeID == nodeID {
			r.logger.Debug("Deleting entry due to removed node", logfields.NodeID, nodeID)
			return true
		}
		return false
	})
}

func (r *authMapGarbageCollector) remoteNodeIDs(node nodeTypes.Node) []uint16 {
	var remoteNodeIDs []uint16

	for _, addr := range node.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			nodeID, exists := r.nodeIDHandler.GetNodeID(addr.IP)
			if !exists {
				// This might be the case at startup, when new nodes aren't yet known to the nodehandler
				// and therefore no node id has been assigned to them.
				r.logger.Debug("No node ID available for node IP - skipping",
					logfields.NodeName, node.Name,
					logfields.IPAddr, addr.IP)
				continue
			}
			remoteNodeIDs = append(remoteNodeIDs, nodeID)
		}
	}

	return remoteNodeIDs
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
		authTypes := r.policyRepo.GetAuthTypes(key.localIdentity, key.remoteIdentity)

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
