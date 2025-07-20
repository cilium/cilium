// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"github.com/cilium/cilium/pkg/identity"
)

// Observer can sign up to receive events whenever local identities are removed.
type Observer interface {
	// LocalEndpointIdentityAdded is called when an identity first becomes
	// used on the node. Implementations must ensure that the callback
	// returns within a reasonable period.
	LocalEndpointIdentityAdded(*identity.Identity)

	// LocalEndpointIdentityRemoved is called when an identity is no longer
	// in use on the node. Implementations must ensure that the callback
	// returns within a reasonable period.
	LocalEndpointIdentityRemoved(*identity.Identity)
}
