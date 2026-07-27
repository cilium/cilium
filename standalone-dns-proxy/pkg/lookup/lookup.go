// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
)

type rulesClient struct {
	logger                *slog.Logger
	prefixToIdentityTable statedb.RWTable[client.PrefixToIdentity]
	ipToIdentityTable     statedb.RWTable[client.IPtoEndpointInfo]
	db                    *statedb.DB
	// prefixLengths tracks the unique set of prefix lengths for IPv4 and
	// IPv6 addresses in order to optimize longest prefix match lookups.
	prefixLengths *counter.PrefixLengthCounter
}

// This is not used by the standalone DNS proxy because it is used by cilium agent to look up DNS rules
// from the in agent dns proxy.
func (r *rulesClient) LookupByIdentity(nid identity.NumericIdentity) []string {
	return []string{}
}

// Note: isHost is always false because the standalone DNS proxy does not handle host endpoints yet.
func (r *rulesClient) LookupRegisteredEndpoint(endpointAddr netip.Addr) (endpt *endpoint.Endpoint, isHost bool, err error) {
	info, _, found := r.ipToIdentityTable.Get(r.db.ReadTxn(), client.IdIPToEndpointIndex.Query(endpointAddr))
	if !found {
		return nil, false, nil
	}
	return &endpoint.Endpoint{
		ID: uint16(info.ID),
		SecurityIdentity: &identity.Identity{
			ID: info.Identity,
		},
	}, false, nil
}

// LookupSecIDByIP looks up the security ID for a given IP address
// It is similar to ipcache.LookupSecIDByIP
func (r *rulesClient) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	if !ip.IsValid() {
		return ipcache.Identity{}, false
	}
	txn := r.db.ReadTxn()
	info, _, found := r.ipToIdentityTable.Get(txn, client.IdIPToEndpointIndex.Query(ip))
	if found {
		return ipcache.Identity{
			ID:     info.Identity,
			Source: source.Local,
		}, true
	}

	ipv6Prefixes, ipv4Prefixes := r.prefixLengths.ToBPFData()
	prefixes := ipv4Prefixes
	if ip.Is6() {
		prefixes = ipv6Prefixes
	}
	for _, prefixLen := range prefixes {
		cidr, _ := ip.Prefix(prefixLen)
		if id, ok := r.lookupPrefix(txn, cidr); ok {
			return id, ok
		}
	}

	return ipcache.Identity{}, false
}

func (r *rulesClient) lookupPrefix(txn statedb.ReadTxn, prefix netip.Prefix) (identity ipcache.Identity, exists bool) {
	if _, cidr, err := net.ParseCIDR(prefix.String()); err == nil {
		ones, bits := cidr.Mask.Size()
		if ones == bits {
			info, _, exists := r.prefixToIdentityTable.Get(txn, client.PrefixToIdentityIndex.Query(prefix))
			if exists {
				return ipcache.Identity{
					ID:     info.Identity,
					Source: source.Local,
				}, exists
			}
		}
	}
	info, _, exists := r.prefixToIdentityTable.Get(txn, client.PrefixToIdentityIndex.Query(prefix))
	return ipcache.Identity{
		ID:     info.Identity,
		Source: source.Local,
	}, exists
}

func (r *rulesClient) watchPrefixToIdentityTable(ctx context.Context, _ cell.Health) error {
	// listen for changes in the prefixToIdentityTable
	wtxn := r.db.WriteTxn(r.prefixToIdentityTable)
	defer wtxn.Abort()
	changeIterator, err := r.prefixToIdentityTable.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	for {
		// Iterate over the changed objects.
		changes, watch := changeIterator.Next(r.db.ReadTxn())
		for change := range changes {
			r.logger.Debug("Detected change in Prefix to Identity mapping", logfields.Object, change)
			for _, prefix := range change.Object.Prefix {
				if change.Deleted {
					r.prefixLengths.Delete([]netip.Prefix{prefix})
				} else {
					r.prefixLengths.Add([]netip.Prefix{prefix})
				}
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}
