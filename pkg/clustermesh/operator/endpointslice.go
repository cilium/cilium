// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"maps"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/equality"
)

// EndpointSliceEqualsForMirroring compares all the relevant fields to
// mirroring in the context of MCS-API and EndpointSliceSync. It ignores
// annotations as those are not mirrored and may be locally changed similar
// to the regular EndpointSlice controller in kube-controller-manager.
func EndpointSliceEqualsForMirroring(a, b *discoveryv1.EndpointSlice) bool {
	return maps.Equal(a.Labels, b.Labels) &&
		equality.Semantic.DeepEqual(a.OwnerReferences, b.OwnerReferences) &&
		a.AddressType == b.AddressType &&
		equality.Semantic.DeepEqual(a.Endpoints, b.Endpoints) &&
		equality.Semantic.DeepEqual(a.Ports, b.Ports)
}
