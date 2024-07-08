// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

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
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

type authMapGarbageCollector struct {
	logger        logrus.FieldLogger
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
	GetAuthTypes(localID, remoteID identity.NumericIdentity) policy.AuthTypes
}

func newAuthMapGC(logger logrus.FieldLogger, authmap authMap, nodeIDHandler datapathTypes.NodeIDHandler, policyRepo policyRepository) *authMapGarbageCollector {
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
		r.logger.
			WithField("name", newNode.Identity().Name).
			WithField("cluster", newNode.Identity().Cluster).
			WithField("node_ids", remoteNodeIDs).
			Debug("Node discovered - mark to keep")
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
	r.logger.
		WithField("name", deletedNode.Identity().Name).
		WithField("cluster", deletedNode.Identity().Cluster).
		WithField("node_ids", remoteNodeIDs).
		Debug("Node deleted - mark for deletion")
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
			r.logger.
				WithField("remote_node_id", key.remoteNodeID).
				Debug("Deleting entry due to removed remote node")
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
			r.logger.
				WithField("node_id", nodeID).
				Debug("Deleting entry due to removed node")
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
				r.logger.
					WithField(logfields.NodeName, node.Name).
					WithField(logfields.IPAddr, addr.IP).
					Debug("No node ID available for node IP - skipping")
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
			r.logger.
				WithField(logfields.Identity, e.ID).
				WithField(logfields.Labels, e.Labels).
				Debug("Identity discovered - mark to keep")
			r.ciliumIdentitiesDiscovered[e.ID] = struct{}{}
		}
	case cache.IdentityChangeSync:
		r.logger.Debug("Identities synced")
		r.ciliumIdentitiesSynced = true
	case cache.IdentityChangeDelete:
		r.logger.
			WithField(logfields.Identity, e.ID).
			WithField(logfields.Labels, e.Labels).
			Debug("Identity deleted - mark for deletion")
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
			r.logger.
				WithField("local_identity", key.localIdentity).
				Debug("Deleting entry due to removed local identity")
			return true
		}
		if _, ok := r.ciliumIdentitiesDiscovered[key.remoteIdentity]; !ok {
			r.logger.
				WithField("remote_identity", key.remoteIdentity).
				Debug("Deleting entry due to removed remote identity")
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
			r.logger.
				WithField(logfields.Identity, id).
				Debug("Deleting entry due to removed identity")
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
			r.logger.
				WithField("key", key).
				WithField("auth_type", key.authType).
				Debug("Deleting entry because no policy requires authentication")
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
	r.logger.
		WithField("gc_time", now).
		Debug("Cleaning up expired entries")
	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if info.expiration.Before(now) {
			r.logger.
				WithField("gc_time", now).
				WithField("expiration", info.expiration).
				Debug("Deleting entry due to expiration")
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
	r.endpointsCacheMutex.Lock()
	r.endpointsCache = map[uint16]*endpoint.Endpoint{}
	for _, ep := range endpointManager.GetEndpoints() {
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
		r.logger.WithError(err).Warning("failed to cleanup auth map entries related to endpoint entries")
	}
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
			r.logger.
				WithField(logfields.Identity, id).
				Debug("Deleting identity entry due to removed endpoint")
			return true
		}
		return false
	})
}
