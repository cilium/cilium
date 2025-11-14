// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// BuildBackendTLSPolicyLookup builds a lookup map of BackendTLSPolicy by the NamespacedName of referenced
// backend Services. These are deduplicated using the Gateway API conflict resolution rules (oldest wins, then
// first lexicographically wins).
func BuildBackendTLSPolicyLookup(btlspList *gatewayv1.BackendTLSPolicyList) map[types.NamespacedName]gatewayv1.BackendTLSPolicy {
	lookupMap := make(map[types.NamespacedName]gatewayv1.BackendTLSPolicy)

	for _, btlsp := range btlspList.Items {
		for _, targetRef := range btlsp.Spec.TargetRefs {
			if !IsServiceTargetRef(targetRef) {
				continue
			}

			svcName := types.NamespacedName{
				Name:      string(targetRef.Name),
				Namespace: btlsp.GetNamespace(),
			}

			old, ok := lookupMap[svcName]
			if !ok {
				// If the target isn't there, we can add it.
				lookupMap[svcName] = btlsp
				continue
			}

			if btlsp.ObjectMeta.CreationTimestamp.Before(&old.ObjectMeta.CreationTimestamp) {
				// if the current policy has an older creation time, it wins
				lookupMap[svcName] = btlsp
				continue
			}

			// Otherwise, if there are multiple references to the same Service in the same Policy
			// we shouldn't do anything.
			btlspName := types.NamespacedName{
				Name:      btlsp.GetName(),
				Namespace: btlsp.GetNamespace(),
			}
			oldName := types.NamespacedName{
				Name:      old.GetName(),
				Namespace: old.GetNamespace(),
			}
			if btlspName == oldName {
				continue
			}

			// If the creation timestamps are equal, and they're not the same object, then
			// the lexicographically first one wins.

			if btlspName.String() < oldName.String() {
				lookupMap[svcName] = btlsp
			}
		}
	}
	return lookupMap
}
