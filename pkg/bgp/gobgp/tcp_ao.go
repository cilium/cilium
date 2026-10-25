// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	gobgp "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// TCP-AO (RFC 5925) support.
//
// GoBGP models TCP-AO with server-global keychains that are referenced by name
// from the peer configuration (keychain name + preferred send key ID). Cilium's
// Router API is per-neighbor instead: each Neighbor carries its own keychain.
// The adapter therefore maintains exactly one GoBGP keychain per neighbor,
// named after the neighbor address.
//
// GoBGP does not expose the master keys of a keychain via its API, so the
// adapter keeps a copy of the last applied keychain of each neighbor to be able
// to compute the difference on updates. The difference is applied without
// resetting the BGP session whenever possible (adding / removing keys, rotating
// the send key to another key of the keychain); if the key currently used to
// authenticate the sent segments itself changes, the peer is re-created, which
// resets the session.

const (
	// tcpAOKeychainNamePrefix is the prefix of the names of the TCP-AO keychains managed by the adapter.
	tcpAOKeychainNamePrefix = "cilium-"
)

// tcpAOKeychainName returns the name of the GoBGP TCP-AO keychain of the neighbor with the given address.
func tcpAOKeychainName(addr netip.Addr) string {
	return tcpAOKeychainNamePrefix + addr.String()
}

// tcpAOKeychainUpdate describes the changes needed to bring the GoBGP TCP-AO keychain
// of a neighbor from its current state to the desired one without resetting the session.
type tcpAOKeychainUpdate struct {
	// addKeys are the keys to add (new keys and new versions of changed keys).
	// They must be installed before the peer configuration is updated, as the
	// new send key may be one of them.
	addKeys []types.TCPAOKey
	// deleteChangedKeys are the old versions of the changed keys. They are deleted
	// in the same request which adds their new versions.
	deleteChangedKeys []types.TCPAOKey
	// deleteKeys are the keys removed from the keychain. They are deleted after
	// the peer configuration is updated, as one of them may be the old send key.
	deleteKeys []types.TCPAOKey
}

func (u *tcpAOKeychainUpdate) empty() bool {
	return len(u.addKeys) == 0 && len(u.deleteChangedKeys) == 0 && len(u.deleteKeys) == 0
}

// errTCPAOResetRequired is returned by planTCPAOKeychainUpdate when the desired
// change can not be applied without resetting the BGP session.
var errTCPAOResetRequired = errors.New("TCP-AO change requires session reset")

// planTCPAOKeychainUpdate computes the keychain update needed to move from the
// current to the desired TCP-AO configuration without resetting the session.
// Returns errTCPAOResetRequired if the key used to authenticate the sent segments
// changes its content, which is not possible without resetting the session.
func planTCPAOKeychainUpdate(current, desired *types.NeighborTCPAO) (*tcpAOKeychainUpdate, error) {
	update := &tcpAOKeychainUpdate{}

	for _, newKey := range desired.Keys {
		oldKey := current.Key(newKey.SendID)
		switch {
		case oldKey == nil:
			update.addKeys = append(update.addKeys, newKey)
		case !oldKey.DeepEqual(&newKey):
			if oldKey.SendID == current.SendID {
				// GoBGP (rightfully) refuses to delete the key currently used for sending.
				return nil, fmt.Errorf("%w: key with send ID %d is in use", errTCPAOResetRequired, oldKey.SendID)
			}
			update.deleteChangedKeys = append(update.deleteChangedKeys, *oldKey)
			update.addKeys = append(update.addKeys, newKey)
		}
	}
	for _, oldKey := range current.Keys {
		if desired.Key(oldKey.SendID) == nil {
			update.deleteKeys = append(update.deleteKeys, oldKey)
		}
	}
	return update, nil
}

// getTCPAOKeychain returns the last applied TCP-AO keychain of the neighbor, or nil if none.
func (g *GoBGPServer) getTCPAOKeychain(addr netip.Addr) *types.NeighborTCPAO {
	g.tcpAOMutex.Lock()
	defer g.tcpAOMutex.Unlock()
	return g.tcpAOKeychains[addr]
}

// setTCPAOKeychain records the TCP-AO keychain applied for the neighbor. Passing nil forgets it.
func (g *GoBGPServer) setTCPAOKeychain(addr netip.Addr, t *types.NeighborTCPAO) {
	g.tcpAOMutex.Lock()
	defer g.tcpAOMutex.Unlock()
	if t == nil {
		delete(g.tcpAOKeychains, addr)
		return
	}
	g.tcpAOKeychains[addr] = cloneTCPAO(t)
}

// addTCPAOKeychain creates the GoBGP keychain of the neighbor with the given keys.
// A stale keychain with the same name (e.g. left over from a previously failed
// operation) is replaced.
func (g *GoBGPServer) addTCPAOKeychain(ctx context.Context, addr netip.Addr, t *types.NeighborTCPAO) error {
	name := tcpAOKeychainName(addr)
	req := &gobgp.AddTcpAoKeychainRequest{Keychain: toGoBGPTCPAOKeychain(name, t)}

	err := g.server.AddTcpAoKeychain(ctx, req)
	if status.Code(err) == codes.AlreadyExists {
		g.logger.Debug("Replacing stale TCP-AO keychain", types.PeerLogField, addr)
		if err := g.server.DeleteTcpAoKeychain(ctx, &gobgp.DeleteTcpAoKeychainRequest{Name: name}); err != nil {
			return fmt.Errorf("failed to delete stale TCP-AO keychain %s: %w", name, err)
		}
		err = g.server.AddTcpAoKeychain(ctx, req)
	}
	if err != nil {
		return fmt.Errorf("failed to add TCP-AO keychain %s: %w", name, err)
	}
	g.setTCPAOKeychain(addr, t)
	return nil
}

// deleteTCPAOKeychain removes the GoBGP keychain of the neighbor. A missing keychain is not an error.
func (g *GoBGPServer) deleteTCPAOKeychain(ctx context.Context, addr netip.Addr) error {
	name := tcpAOKeychainName(addr)
	err := g.server.DeleteTcpAoKeychain(ctx, &gobgp.DeleteTcpAoKeychainRequest{Name: name})
	if err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("failed to delete TCP-AO keychain %s: %w", name, err)
	}
	g.setTCPAOKeychain(addr, nil)
	return nil
}

// updateTCPAOKeys applies a key add / delete request to the GoBGP keychain of the neighbor.
func (g *GoBGPServer) updateTCPAOKeys(ctx context.Context, addr netip.Addr, add, del []types.TCPAOKey) error {
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	name := tcpAOKeychainName(addr)
	req := &gobgp.UpdateTcpAoKeychainRequest{
		Name:    name,
		AddKeys: toGoBGPTCPAOKeys(add),
	}
	for _, k := range del {
		req.DeleteKeys = append(req.DeleteKeys, toGoBGPTCPAOKeyID(k))
	}
	if _, err := g.server.UpdateTcpAoKeychain(ctx, req); err != nil {
		return fmt.Errorf("failed to update TCP-AO keychain %s: %w", name, err)
	}
	return nil
}

// tcpAOPeerUpdate describes how the TCP-AO configuration of an existing peer is being changed.
type tcpAOPeerUpdate struct {
	// resetPeer is set when the change can only be applied by re-creating the peer.
	resetPeer bool
	// deleteKeychain is set when the keychain has to be deleted after the peer update
	// (TCP-AO is being disabled for the peer).
	deleteKeychain bool
	// keychainUpdate holds the keys to add / delete, when the change is applied in-place.
	keychainUpdate *tcpAOKeychainUpdate
}

// prepareTCPAOUpdate performs the TCP-AO keychain operations which have to happen
// before the GoBGP peer configuration is updated, and returns the operations which
// have to happen after it.
func (g *GoBGPServer) prepareTCPAOUpdate(ctx context.Context, n *types.Neighbor, oldPeer *gobgp.Peer) (*tcpAOPeerUpdate, error) {
	res := &tcpAOPeerUpdate{}
	oldEnabled := oldPeer != nil && oldPeer.TcpAo != nil && oldPeer.TcpAo.Keychain != ""

	switch {
	case n.TCPAO == nil && !oldEnabled:
		// TCP-AO not in use

	case n.TCPAO != nil && !oldEnabled:
		// enabling TCP-AO: the keychain must exist before the peer references it
		if err := g.addTCPAOKeychain(ctx, n.Address, n.TCPAO); err != nil {
			return nil, err
		}

	case n.TCPAO == nil && oldEnabled:
		// disabling TCP-AO: the keychain can be deleted only once the peer no longer references it
		res.deleteKeychain = true

	default:
		// TCP-AO stays enabled, check for keychain changes
		current := g.getTCPAOKeychain(n.Address)
		if current == nil || oldPeer.TcpAo.Keychain != tcpAOKeychainName(n.Address) {
			// The keychain is unknown to us (should not happen), re-create the peer from scratch.
			g.logger.Warn("Unknown TCP-AO keychain configured for the peer, re-creating the peer",
				types.PeerLogField, n.Address,
				logfields.Name, oldPeer.TcpAo.Keychain,
			)
			res.resetPeer = true
			return res, nil
		}
		if current.DeepEqual(n.TCPAO) {
			return res, nil
		}
		update, err := planTCPAOKeychainUpdate(current, n.TCPAO)
		if err != nil {
			g.logger.Info("TCP-AO keychain change can not be applied in-place, re-creating the peer",
				types.PeerLogField, n.Address,
				logfields.Reason, err,
			)
			res.resetPeer = true
			return res, nil
		}
		// install the new keys (and the new versions of the changed keys) before the peer update
		if err := g.updateTCPAOKeys(ctx, n.Address, update.addKeys, update.deleteChangedKeys); err != nil {
			return nil, err
		}
		res.keychainUpdate = update
	}
	return res, nil
}

// finishTCPAOUpdate performs the TCP-AO keychain operations which have to happen
// after the GoBGP peer configuration has been updated.
func (g *GoBGPServer) finishTCPAOUpdate(ctx context.Context, n *types.Neighbor, u *tcpAOPeerUpdate) error {
	if u.deleteKeychain {
		return g.deleteTCPAOKeychain(ctx, n.Address)
	}
	if u.keychainUpdate != nil {
		// the old send key is not in use anymore, the removed keys can be deleted now
		if err := g.updateTCPAOKeys(ctx, n.Address, nil, u.keychainUpdate.deleteKeys); err != nil {
			return err
		}
	}
	if n.TCPAO != nil {
		g.setTCPAOKeychain(n.Address, n.TCPAO)
	}
	return nil
}

// validateNeighborAuth validates the authentication parameters of the neighbor.
func validateNeighborAuth(n *types.Neighbor) error {
	if n.TCPAO != nil && n.AuthPassword != "" {
		return fmt.Errorf("TCP-AO and TCP MD5 password are mutually exclusive")
	}
	if err := n.TCPAO.Validate(); err != nil {
		return fmt.Errorf("invalid TCP-AO configuration: %w", err)
	}
	return nil
}

// cloneTCPAO returns a deep copy of the keychain.
func cloneTCPAO(t *types.NeighborTCPAO) *types.NeighborTCPAO {
	if t == nil {
		return nil
	}
	res := &types.NeighborTCPAO{
		SendID: t.SendID,
		Keys:   make([]types.TCPAOKey, 0, len(t.Keys)),
	}
	for _, k := range t.Keys {
		k.MasterKey = slices.Clone(k.MasterKey)
		res.Keys = append(res.Keys, k)
	}
	return res
}
