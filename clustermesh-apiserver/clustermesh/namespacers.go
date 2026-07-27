// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"k8s.io/apimachinery/pkg/runtime"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
)

type GenericNamespacer[T runtime.Object] struct {
	extract func(T) string
}

func (gn *GenericNamespacer[T]) ExtractNamespace(event resource.Event[T]) (namespace string) {
	return gn.extract(event.Object)
}

// ----- CiliumIdentity ----- //

func newCiliumIdentityNamespacer() Namespacer[*cilium_api_v2.CiliumIdentity] {
	return &GenericNamespacer[*cilium_api_v2.CiliumIdentity]{
		extract: func(obj *cilium_api_v2.CiliumIdentity) string {
			return obj.SecurityLabels[cmk8s.PodPrefixLbl]
		},
	}
}

// ----- CiliumEndpoint ----- //

func newCiliumEndpointNamespacer() Namespacer[*types.CiliumEndpoint] {
	return &GenericNamespacer[*types.CiliumEndpoint]{
		extract: func(obj *types.CiliumEndpoint) string {
			return obj.Namespace
		},
	}
}

// ----- CiliumEndpointSlice ----- //

func newCiliumEndpointSliceNamespacer() Namespacer[*cilium_api_v2a1.CiliumEndpointSlice] {
	return &GenericNamespacer[*cilium_api_v2a1.CiliumEndpointSlice]{
		extract: func(obj *cilium_api_v2a1.CiliumEndpointSlice) string {
			return obj.Namespace
		},
	}
}
