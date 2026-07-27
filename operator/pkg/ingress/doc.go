// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ingress contains all the logic for Cilium Ingress Controller.
// Only Ingress resources having annotations."kubernetes.io/ingress.class"
// or spec.ingressClassName set to "cilium" are managed and processed by the
// Cilium Ingress Controller.
//
// Two LB modes are supported:
//   - dedicated LB mode: a dedicated LB is used for each Ingress.
//   - shared LB mode: all eligible Ingresses are using the same LB.
//
// Each LB mode will have its own translation logic, which converts Ingress
// resource(s) into internal representation, and then turns it into a set of
// Cilium configurations (e.g. CiliumEnvoyConfig, LB Service, Endpoints etc.).
//   - Create one Load Balancer service, the external IP/FQDN is available will
//     bubble up to Ingress status once ready. (dedicated LB mode only)
//   - Create dummy Endpoint for above LB service. (dedicated LB mode only)
//   - Create CiliumEnvoyConfig with all routing details. (both modes)
//
// There is a small secret sync component, which will watch all tls ingress secrets
// and sync them to another give namespace. This is to limit the permission during
// runtime in all nodes.
package ingress
