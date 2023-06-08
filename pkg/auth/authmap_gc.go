// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node/addressing"
)

type authMapGarbageCollector struct {
	authmap authMap
	ipCache ipCache

	discoveredCiliumNodeIDs    map[uint16]struct{}
	discoveredCiliumIdentities map[identity.NumericIdentity]struct{}
}

func newAuthMapGC(authmap authMap, ipCache ipCache) *authMapGarbageCollector {
	return &authMapGarbageCollector{
		authmap: authmap,
		ipCache: ipCache,
		discoveredCiliumNodeIDs: map[uint16]struct{}{
			0: {}, // Local node 0 is always available
		},
		discoveredCiliumIdentities: map[identity.NumericIdentity]struct{}{},
	}
}

func (r *authMapGarbageCollector) handleCiliumNodeEvent(_ context.Context, e resource.Event[*ciliumv2.CiliumNode]) (err error) {
	defer func() { e.Done(err) }()

	switch e.Kind {
	case resource.Upsert:
		if r.discoveredCiliumNodeIDs != nil {
			log.Debug("auth: nodes discovered - getting node id")
			remoteNodeIDs := r.remoteNodeIDs(e.Object)
			for _, rID := range remoteNodeIDs {
				r.discoveredCiliumNodeIDs[rID] = struct{}{}
			}
		}
	case resource.Sync:
		log.Debug("auth: nodes synced - cleaning up missing nodes")
		if err = r.cleanupMissingNodes(); err != nil {
			return fmt.Errorf("failed to cleanup missing nodes: %w", err)
		}
		r.discoveredCiliumNodeIDs = nil
	case resource.Delete:
		log.Debugf("auth: node deleted - cleaning up: %s", e.Key.Name)
		if err = r.cleanupDeletedNode(e.Object); err != nil {
			return fmt.Errorf("failed to cleanup deleted node: %w", err)
		}
	}
	return nil
}

func (r *authMapGarbageCollector) handleCiliumIdentityEvent(_ context.Context, e resource.Event[*ciliumv2.CiliumIdentity]) (err error) {
	defer func() { e.Done(err) }()

	switch e.Kind {
	case resource.Upsert:
		if r.discoveredCiliumIdentities != nil {
			log.Debug("auth: identities discovered")
			var id identity.NumericIdentity
			id, err = identity.ParseNumericIdentity(e.Object.Name)
			if err != nil {
				return fmt.Errorf("failed to parse identity: %w", err)
			}
			r.discoveredCiliumIdentities[id] = struct{}{}
		}
	case resource.Sync:
		log.Debug("auth: identities synced - cleaning up missing identities")
		if err = r.cleanupMissingIdentities(); err != nil {
			return fmt.Errorf("failed to cleanup missing identities: %w", err)
		}
	case resource.Delete:
		log.Debugf("auth: identity deleted - cleaning up: %s", e.Key.Name)
		if err = r.cleanupDeletedIdentity(e.Object); err != nil {
			return fmt.Errorf("failed to cleanup deleted identity: %w", err)
		}
		r.discoveredCiliumIdentities = nil
	}
	return nil
}

func (r *authMapGarbageCollector) cleanupMissingNodes() error {
	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if _, ok := r.discoveredCiliumNodeIDs[key.remoteNodeID]; !ok {
			log.Debugf("auth: deleting entry due to removed remote node: %d", key.remoteNodeID)
			return true
		}
		return false
	})
}

func (r *authMapGarbageCollector) cleanupMissingIdentities() error {
	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if _, ok := r.discoveredCiliumIdentities[key.localIdentity]; !ok {
			log.Debugf("auth: deleting entry due to removed local identity: %d", key.localIdentity)
			return true
		}
		if _, ok := r.discoveredCiliumIdentities[key.remoteIdentity]; !ok {
			log.Debugf("auth: deleting entry due to removed remote identity: %d", key.remoteIdentity)
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
				log.Debugf("auth: deleting entry due to removed node: %d", id)
				return true
			}
		}
		return false
	})
}

func (r *authMapGarbageCollector) cleanupDeletedIdentity(id *ciliumv2.CiliumIdentity) error {
	idNumeric, err := identity.ParseNumericIdentity(id.Name)
	if err != nil {
		return fmt.Errorf("failed to parse deleted identity: %w", err)
	}

	return r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if key.localIdentity == idNumeric || key.remoteIdentity == idNumeric {
			log.Debugf("auth: deleting entry due to removed identity: %d", idNumeric)
			return true
		}
		return false
	})
}

func (r *authMapGarbageCollector) CleanupExpiredEntries(_ context.Context) error {
	log.Debug("auth: cleaning up expired entries")
	now := time.Now()
	err := r.authmap.DeleteIf(func(key authKey, info authInfo) bool {
		if info.expiration.Before(now) {
			log.Debugf("auth: deleting entry due to expiration: %s", info.expiration)
			return true
		}
		return false
	})

	if err != nil {
		return fmt.Errorf("failed to cleanup expired entries: %w", err)
	}
	return nil
}

func (r *authMapGarbageCollector) remoteNodeIDs(node *ciliumv2.CiliumNode) []uint16 {
	var remoteNodeIDs []uint16

	for _, addr := range node.Spec.Addresses {
		if addr.Type == addressing.NodeInternalIP {
			remoteNodeIDs = append(remoteNodeIDs, r.ipCache.AllocateNodeID(net.ParseIP(addr.IP)))
		}
	}

	return remoteNodeIDs
}
