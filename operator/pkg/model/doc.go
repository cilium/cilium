// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package model contains a data model for translations from upstream Kubernetes
// resources to Cilium Kubernetes resources.
//
// Initially, used for Ingress to CiliumEnvoyConfig translation to enable
// shared load balancing, but will be used for other things in the future
// (such as Gateway API support).
package model
