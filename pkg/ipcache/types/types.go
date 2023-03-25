// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/identity/cache"
)

// PolicyHandler is responsible for handling identity updates into the core
// policy engine. See SelectorCache.UpdateIdentities() for more details.
type PolicyHandler interface {
	UpdateIdentities(added, deleted cache.IdentityCache, wg *sync.WaitGroup)
}

// DatapathHandler is responsible for ensuring that policy updates in the
// core policy engine are pushed into the underlying BPF policy maps, to ensure
// that the policies are actively being enforced in the datapath for any new
// identities that have been updated using 'PolicyHandler'.
//
// Wait on the returned sync.WaitGroup to ensure that the operation is complete
// before updating the datapath's IPCache maps.
type DatapathHandler interface {
	UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup
}

// ResourceID identifies a unique copy of a resource that provides a source for
// information tied to an IP address in the IPCache.
type ResourceID string

// ResourceKind determines the source of the ResourceID. Typically this is the
// short name for the k8s resource.
type ResourceKind string

var (
	ResourceKindEndpoint             = ResourceKind("ep")
	ResourceKindEndpointSlice        = ResourceKind("endpointslices")
	ResourceKindEndpointSlicev1beta1 = ResourceKind("endpointslices_v1beta1")
	ResourceKindNode                 = ResourceKind("node")
)

// NewResourceID returns a ResourceID populated with the standard fields for
// uniquely identifying a source of IPCache information.
func NewResourceID(kind ResourceKind, namespace, name string) ResourceID {
	str := strings.Builder{}
	str.Grow(len(kind) + 1 + len(namespace) + 1 + len(name))
	str.WriteString(string(kind))
	str.WriteRune('/')
	str.WriteString(namespace)
	str.WriteRune('/')
	str.WriteString(name)
	return ResourceID(str.String())
}

// NodeHandler is responsible for the management of node identities.
type NodeHandler interface {
	AllocateNodeID(net.IP) uint16
}
