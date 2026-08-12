// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/node"
)

type endpointRulesOperations struct {
	logger          *slog.Logger
	ipam            *ipam.IPAM
	ipamMode        string
	endpointManager endpointmanager.EndpointManager
	localNodeStore  *node.LocalNodeStore
}

var _ statedbReconciler.Operations[*EndpointRules] = (*endpointRulesOperations)(nil)

func (ops *endpointRulesOperations) Update(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	desired *EndpointRules,
) error {
	result, err := ops.ipam.ResolveRoutingMetadata(desired.Address, "")
	if err != nil {
		return fmt.Errorf("resolve routing metadata for %s: %w", desired.Address, err)
	}

	var options []linuxrouting.RoutingInfoOption
	// Azure uses the legacy ifindex-based priority/table scheme. ENI and
	// AlibabaCloud use the interface-number-based scheme.
	if ops.ipamMode == ipamOption.IPAMAzure {
		options = append(options, linuxrouting.WithCompatEgressPriority())
	}

	info, err := linuxrouting.NewRoutingInfo(
		result.GatewayIP.String(),
		result.PrimaryMAC,
		result.InterfaceNumber,
		options...,
	)
	if err != nil {
		return fmt.Errorf("build routing information for %s: %w", desired.Address, err)
	}

	if err := info.ReconcileEndpointRules(desired.Address, false); err != nil {
		return fmt.Errorf("reconcile endpoint routing rules for %s: %w", desired.Address, err)
	}
	return nil
}

func (ops *endpointRulesOperations) Delete(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	desired *EndpointRules,
) error {
	if err := linuxrouting.DeleteRulesIfExists(ops.logger, desired.Address); err != nil {
		return fmt.Errorf("delete endpoint routing rules for %s: %w", desired.Address, err)
	}
	return nil
}

func (ops *endpointRulesOperations) Prune(
	ctx context.Context,
	_ statedb.ReadTxn,
	objects iter.Seq2[*EndpointRules, statedb.Revision],
) error {
	desired := sets.New[netip.Addr]()
	for obj := range objects {
		desired.Insert(obj.Address)
	}

	infraAddrs, err := infrastructureAddresses(ctx, ops.localNodeStore)
	if err != nil {
		return err
	}

	return linuxrouting.GCOrphanRules(ops.logger, func(addr netip.Addr) bool {
		// The address is still present in the desired state.
		if desired.Has(addr) {
			return false
		}
		// The address belongs to local infrastructure.
		if infraAddrs.Has(addr) {
			return false
		}
		// The endpoint manager still has a live owner for the address.
		if ops.endpointManager.LookupIP(addr) != nil {
			return false
		}
		// Preserve IPAM allocations that may not have reached desired state yet.
		return !ops.ipam.IsAllocatedIP(addr)
	})
}

func infrastructureAddresses(ctx context.Context, localNodeStore *node.LocalNodeStore) (sets.Set[netip.Addr], error) {
	localNode, err := localNodeStore.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("get local node infrastructure addresses: %w", err)
	}

	protected := sets.New[netip.Addr]()
	add := func(addr netip.Addr) {
		if addr.IsValid() {
			protected.Insert(addr)
		}
	}

	add(localNode.IPv4HealthIP.Addr)
	add(localNode.IPv6HealthIP.Addr)
	for _, raw := range []net.IP{
		localNode.IPv4IngressIP,
		localNode.IPv6IngressIP,
		localNode.GetCiliumInternalIP(false),
		localNode.GetCiliumInternalIP(true),
	} {
		if addr, ok := netip.AddrFromSlice(raw); ok {
			// LocalNode's legacy net.IP fields may represent IPv4 addresses as
			// IPv4-mapped IPv6 addresses.
			add(addr.Unmap())
		}
	}
	return protected, nil
}
