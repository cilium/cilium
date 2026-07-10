// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
)

// Restorer wraps a method to wait for endpoints restoration.
type Restorer interface {
	// WaitForEndpointRestoreWithoutRegeneration blocks the caller until either the context is
	// cancelled or all the endpoints from a previous run have been restored.
	WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error

	// WaitForEndpointRestore blocks the caller until either the context is
	// cancelled or all the endpoints from a previous run have been restored and regenerated.
	WaitForEndpointRestore(ctx context.Context) error

	// WaitForInitialPolicy blocks the caller until either the context is
	// cancelled or initial policies of all restored endpoints have been computed.
	WaitForInitialPolicy(ctx context.Context) error
}

// RestorationNotifier is implemented by components that need to be restored with the "old" endpoints
// that have been read from disk by the Endpoint restorer.
// Components should register with Hive value groups by using RestorationNotifierOut.
type RestorationNotifier interface {
	// RestorationNotify is called once the "old" endpoints have been read from disk.
	// The Endpoints are not yet exposed to the EndpointManager.
	RestorationNotify(possible map[uint16]*endpoint.Endpoint)
}

type RestorationNotifierOut struct {
	cell.Out

	Restorer RestorationNotifier `group:"endpointRestorationNotifiers"`
}
