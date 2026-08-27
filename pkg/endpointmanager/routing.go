// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
)

// EndpointRoutingWaiter waits until agent-managed routes and rules for cloud
// vendor IPAM endpoints have been reconciled. It is called after
// EndpointManager.AddEndpoint has returned.
type EndpointRoutingWaiter interface {
	WaitForEndpointRouting(context.Context, *endpoint.Endpoint) error
}
