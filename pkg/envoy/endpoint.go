// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envoy

import (
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

// NetworkPolicyEndpoint describes the parts of the Endpoint that are relevant
// to configuring NetworkPolicy in Envoy. This is a subset of `Endpoint`.
type NetworkPolicyEndpoint interface {
	logger.EndpointInfoSource

	// OnProxyPolicyUpdate is called when the proxy acknowledges that it
	// has applied a policy.
	OnProxyPolicyUpdate(policyRevision uint64)

	// UpdateProxyRedirectStatistics updates the Endpoint's proxy redirect
	// statistics to account for a new observed flow with the given
	// characteristics.
	UpdateProxyRedirectStatistics(l7Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict)
}
