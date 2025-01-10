// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package translation building block for translation from model to CiliumEnvoyConfig, Service, etc.
// Translator is the interface to take the model and generate required CiliumEnvoyConfig,
// LoadBalancer Service, Endpoint, etc.
//
// Additional, this package also contains a bare minimum constructors for common Envoy resources:
// - Cluster
// - Listener
// - HTTP Connection Manager
// - RouteConfiguration
// - VirtualHost
//
// Each type of resource can be extended to support more features and use cases with mutation functions.
package translation
