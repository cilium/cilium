// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2019 The Kubernetes Authors.

package v1beta1

const (
	// LabelServiceName is used to indicate the name of a Kubernetes service.
	LabelServiceName = "kubernetes.io/service-name"
	// LabelManagedBy is used to indicate the controller or entity that manages
	// an EndpointSlice. This label aims to enable different EndpointSlice
	// objects to be managed by different controllers or entities within the
	// same cluster. It is highly recommended to configure this label for all
	// EndpointSlices.
	LabelManagedBy = "endpointslice.kubernetes.io/managed-by"
	// LabelSkipMirror can be set to true on an Endpoints resource to indicate
	// that the EndpointSliceMirroring controller should not mirror this
	// resource with EndpointSlices.
	LabelSkipMirror = "endpointslice.kubernetes.io/skip-mirror"
)
