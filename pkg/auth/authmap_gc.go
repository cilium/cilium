// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/policy"
)

type authMapGarbageCollector struct {
	logger     logrus.FieldLogger
	authmap    authMap
	ipCache    ipCache
	policyRepo policyRepository

	discoveredCiliumNodeIDs map[uint16]struct{}

	ciliumIdentitiesMutex      lock.Mutex
	ciliumIdentitiesDiscovered map[identity.NumericIdentity]struct{}
	ciliumIdentitiesSynced     bool
	ciliumIdentitiesDeleted    map[identity.NumericIdentity]struct{}
}

type policyRepository interface {
	GetAuthTypes(localID, remoteID identity.NumericIdentity) policy.AuthTypes
}

func newAuthMapGC(logger logrus.FieldLogger, authmap authMap, ipCache ipCache, policyRepo policyRepository) *authMapGarbageCollector {
	return &authMapGarbageCollector{
		logger:     logger,
		authmap:    authmap,
		ipCache:    ipCache,
		policyRepo: policyRepo,

		discoveredCiliumNodeIDs: map[uint16]struct{}{
			0: {}, // Local node 0 is always available
		},
		ciliumIdentitiesDiscovered: map[identity.NumericIdentity]struct{}{},
		ciliumIdentitiesDeleted:    map[identity.NumericIdentity]struct{}{},
	}
}

// Nodes

func (r *authMapGarbageCollector) handleCiliumNodeEvent(_ context.Context, e resource.Event[*ciliumv2.CiliumNode]) (err error) {
	defer func() { e.Done(err) }()

	switch e.Kind {
	case resource.Upsert:
		if r.discoveredCiliumNodeIDs != nil {
			r.logger.
				WithField("key", e.Key).
				Debug("Node discovered - getting node id")
			remoteNodeIDs := r.remoteNodeIDs(e.Object)
			for _, rID := range remoteNodeIDs {
				r.discoveredCiliumNodeIDs[rID] = struct{}{}
			}
		}
	case resource.Sync:
		r.logger.Debug("Nodes synced - cleaning up missing nodes")
		if err = r.cleanupMissingNodes(); err != nil {
			return fmt.Errorf("failed to cleanup missing nodes: %w", err)
		}
		r.discoveredCiliumNodeIDs = nil
	case resource.Delete:
		r.logger.
			WithField("key", e.Key).
			Debug("Node deleted - cleaning up")
		if err = r.cleanupDeletedNode(e.Object); err != nil {
			return fmt.Errorf("failed to cleanup deleted node: %w", err)
		}
	}
	return nil
}

func (r *authMapGarbageCollector) cleanupMissingNodes() error {
	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if _, ok := r.discoveredCiliumNodeIDs[key.remoteNodeID]; !ok {
			r.logger.
				WithField("remote_node_id", key.remoteNodeID).
				Debug("Deleting entry due to removed remote node")
			return true
		}
		return false
	})
}

func (r *authMapGarbageCollector) cleanupDeletedNode(node *ciliumv2.CiliumNode) error {
	remoteNodeIDs := r.remoteNodeIDs(node)

	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		for _, id := range remoteNodeIDs {
			if key.remoteNodeID == id {
				r.logger.
					WithField("node_id", id).
					Debug("Deleting entry due to removed node")
				return true
			}
		}
		return false
	})
}

func (r *authMapGarbageCollector) remoteNodeIDs(node *ciliumv2.CiliumNode) []uint16 {
	var remoteNodeIDs []uint16

	for _, addr := range node.Spec.Addresses {
		if addr.Type == addressing.NodeInternalIP {
			nodeID, exists := r.ipCache.GetNodeID(net.ParseIP(addr.IP))
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
	r.logger.Debug("Cleaning up expired entries")

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
	r.logger.Debug("auth: cleaning up expired entries")
	now := time.Now()
	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if info.expiration.Before(now) {
			r.logger.
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
