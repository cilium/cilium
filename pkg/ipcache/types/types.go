// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
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
