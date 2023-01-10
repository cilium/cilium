// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// BGPRouterManager provides a declarative API for defining
// BGP peers.
type BGPRouterManager interface {
	// ConfigurePeers evaluates the provided CiliumBGPPeeringPolicy
	// and the implementation will configure itself to apply this policy.
	//
	// A ControllerState structure is provided which captures Cilium's runtime
	// state at the time of this method's invocation. It must remain read-only.
	//
	// ConfigurePeers should block until it can ensure a subsequent call
	// to ConfigurePeers can occur without conflict.
	//
	// ConfigurePeers should not be called concurrently and expects invocations
	// to be serialized contingent to the method's completion.
	//
	// An error is returned only when the implementation can determine a
	// critical flaw with the peering policy, not when network connectivity
	// is an issue.
	//
	// Providing a nil policy to ConfigurePeers will withdrawal all routes
	// and disconnect from the peers.
	ConfigurePeers(ctx context.Context, policy *v2alpha1api.CiliumBGPPeeringPolicy, state *ControlPlaneState) error
}
