// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
)

// Namespacer is an interface that defines methods to handle namespace-related operations
// for Kubernetes resources in the context of clustermesh synchronization.
type Namespacer[T runtime.Object] interface {
	// ExtractNamespace retrieves the namespace of a given event's object.
	ExtractNamespace(resource.Event[T]) (namespace string, err error)
}

// ----- NoopNamespacer ----- //

type noopNamespacer[T runtime.Object] struct{}

func newNoopNamespacer[T runtime.Object]() Namespacer[T] {
	return &noopNamespacer[T]{}
}

func (n *noopNamespacer[T]) ExtractNamespace(event resource.Event[T]) (namespace string, err error) {
	return namespace, nil
}

// ----- CiliumIdentity ----- //

type ciliumIdentityNamespacer struct{}

func newCiliumIdentityNamespacer() Namespacer[*cilium_api_v2.CiliumIdentity] {
	return &ciliumIdentityNamespacer{}
}

func (n *ciliumIdentityNamespacer) ExtractNamespace(event resource.Event[*cilium_api_v2.CiliumIdentity]) (namespace string, err error) {
	//Check object is not nil.
	if event.Object == nil {
		return namespace, fmt.Errorf("object empty")
	}
	// Get the CiliumIdentity namespace from labels.
	namespace = event.Object.SecurityLabels[cmk8s.PodPrefixLbl]

	if namespace == "" {
		return "", fmt.Errorf("could not determine namespace")
	}
	return namespace, nil
}

// ----- CiliumEndpoint ----- //

type ciliumEndpointNamespacer struct{}

func newCiliumEndpointNamespacer() Namespacer[*types.CiliumEndpoint] {
	return &ciliumEndpointNamespacer{}
}

func (n *ciliumEndpointNamespacer) ExtractNamespace(event resource.Event[*types.CiliumEndpoint]) (namespace string, err error) {
	// Check object is not nil.
	if event.Object == nil {
		return namespace, fmt.Errorf("object empty")
	}
	// Get the CiliumEndpoint namespace from metadata.
	namespace = event.Object.Namespace

	if namespace == "" {
		return "", fmt.Errorf("could not determine namespace")
	}
	return namespace, nil
}

// ----- CiliumEndpointSlice ----- //

type ciliumEndpointSliceNamespacer struct{}

func newCiliumEndpointSliceNamespacer() Namespacer[*cilium_api_v2a1.CiliumEndpointSlice] {
	return &ciliumEndpointSliceNamespacer{}
}

func (n *ciliumEndpointSliceNamespacer) ExtractNamespace(event resource.Event[*cilium_api_v2a1.CiliumEndpointSlice]) (namespace string, err error) {
	// Check object is not nil.
	if event.Object == nil {
		return namespace, fmt.Errorf("object empty")
	}
	// Get the CiliumEndpointSlice namespace from metadata.
	namespace = event.Object.Namespace

	if namespace == "" {
		return "", fmt.Errorf("could not determine namespace")
	}
	return namespace, nil
}
