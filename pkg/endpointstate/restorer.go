// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

import "context"

// Restorer wraps a method to wait for endpoints restoration.
type Restorer interface {
	// WaitForEndpointRestore blocks the caller until either the context is
	// cancelled or all the endpoints have been restored from a previous run.
	WaitForEndpointRestore(ctx context.Context) error

	// WaitForInitialEnvoyPolicy blocks the caller until either the context is
	// cancelled or policies of all the endpoints have been computed.
	WaitForInitialEnvoyPolicy(ctx context.Context) error
}
