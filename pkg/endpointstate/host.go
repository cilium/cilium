// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/promise"
)

// HostEndpointPromise resolves when the host endpoint is ready for use.
type HostEndpointPromise promise.Promise[*endpoint.Endpoint]
