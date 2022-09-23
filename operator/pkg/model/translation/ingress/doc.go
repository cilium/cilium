// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ingress contains the translation logic from Ingress to CiliumEnvoyConfig
// and related resources.
//
// Currently, there is only one translator i.e. shared LB Ingress translator. However,
// the long term goal is to consolidate dedicated LB Ingress translator into this package.
package ingress
