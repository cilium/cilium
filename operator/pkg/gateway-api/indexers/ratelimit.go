// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// IndexRateLimitPolicyByTarget indexes CiliumRateLimitPolicy objects by the 
// full NamespacedName of their target resource (e.g., HTTPRoute).
// This allows for efficient lookup during the reconciliation of Gateways and Routes.
func IndexRateLimitPolicyByTarget(rawObj client.Object) []string {
	policy, ok := rawObj.(*v2alpha1.CiliumRateLimitPolicy)
	if !ok {
		return nil
	}

	target := policy.Spec.TargetRef
	
	// Implementation of Gateway API Policy Attachment logic:
	// 1. We only index policies targeting supported types (HTTPRoute, GRPCRoute).
	// 2. The target must be in the same group (gateway.networking.k8s.io).
	// 3. Since it's a LocalPolicyTargetReference, the namespace is implicitly 
	//    the same as the policy's namespace.
	if target.Group == gatewayv1.Group(gatewayv1.GroupName) &&
		(target.Kind == gatewayv1.Kind("HTTPRoute") || target.Kind == gatewayv1.Kind("GRPCRoute")) {
		
		return []string{
			types.NamespacedName{
				Namespace: policy.Namespace,
				Name:      string(target.Name),
			}.String(),
		}
	}

	return nil
}
