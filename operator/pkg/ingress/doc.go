// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ingress contains all the logic for Cilium Ingress Controller
// For every Ingress object, the controller will check if spec.ingressClassName is cilium,
// then perform the respective operations
// - Create one Load Balancer service, the external IP/FQDN is available will bubble up to
//	 Ingress status once ready.
// - Create CiliumEnvoyConfig with all routing details.
// - Create dummy Endpoint for above LB service
// All above child resources are having respective ownerReferences for proper cleanup.
//
// There is a small secret sync component, which will watch all tls ingress secrets and sync them to another give
// namespace. This is to limit the permission during runtime in all nodes.
package ingress
