// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2020 The Kubernetes Authors.

package v1

const (
	// AnnotationIsDefaultIngressClass can be used to indicate that an
	// IngressClass should be considered default. When a single IngressClass
	// resource has this annotation set to true, new Ingress resources without a
	// class specified will be assigned this default class.
	AnnotationIsDefaultIngressClass = "ingressclass.kubernetes.io/is-default-class"
)
