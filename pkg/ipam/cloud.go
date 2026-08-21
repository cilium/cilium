// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"net/netip"

	"github.com/cilium/hive/cell"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// CloudProvider is the cloud-specific customization of the agent-side
// multi-pool allocator. Exactly one is selected at runtime, by IPAM mode.
//
// Implementations live in pkg/{cloud}/agent and import this package,
// pkg/ipam consumes them through the "ipam-cloud-providers" hive value
// group and imports no cloud-provider package.
//
// This is the agent-side counterpart of operator/pkg/ipam.CloudAllocator.
type CloudProvider interface {
	// Mode returns the IPAM mode this provider handles.
	Mode() string

	// PoolSpecAccessors returns how allocated CIDRs are read from and written
	// back to the CiliumNode for this cloud.
	PoolSpecAccessors() PoolSpecAccessors

	// Initialize performs the cloud-specific startup work that must not block:
	// registering the provider's CiliumNode observers and whatever jobs it needs
	// to configure the node. It is called once, before the multi-pool manager is
	// constructed, and returns the resolver the allocators enrich their results
	// with.
	Initialize() (RoutingMetadataResolver, error)

	// WaitReady blocks until the state the jobs registered by Initialize set in
	// motion has converged and the agent is allowed to serve allocations. A
	// provider with nothing to converge on returns nil immediately.
	//
	// It returns an error if ctx is cancelled first.
	WaitReady(ctx context.Context) error
}

// RoutingMetadataResolver reports the cloud-specific routing metadata of an
// allocated address. It is built by CloudProvider.Initialize.
type RoutingMetadataResolver interface {
	// ResolveRoutingMetadata returns the cloud-specific routing metadata of
	// addr (PrimaryMAC, GatewayIP, CIDRs, InterfaceNumber), reported as the
	// AllocationResult the allocator hands to its caller.
	//
	// Returning an error makes an allocating caller release the reservation
	// that the underlying allocation already took.
	ResolveRoutingMetadata(node *ciliumv2.CiliumNode, addr netip.Addr, pool Pool) (*AllocationResult, error)
}

// CloudProviderOut is returned by each cloud provider cell.
type CloudProviderOut struct {
	cell.Out

	Provider CloudProvider `group:"ipam-cloud-providers"`
}
