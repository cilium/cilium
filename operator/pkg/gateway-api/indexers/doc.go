// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package indexers holds functions related to building indexes for Kubernetes objects
// in the client cache.
//
// Index functions in this package MUST:
//
//   - return a function with signature `func(rawObj client.Object) []string`, where the
//     `[]string` contains a set of values to index that object by. Generally this should
//     be full names (`namespace/name` of a particular related object type).
//
// An example here is the generateIndexerHTTPRouteByBackendService function, which takes
// a client.Client and returns a closure that can index HTTPRoutes by the referenced backend
// service, because ServiceImport support also requires dereferencing a backend Service from
// annotations on the ServiceImport object.
//
// Index functions in this package that are used in reconcilers MUST also:
//   - only operate on a single object (no using a client to GET other objects, for example)
//
// An example here is the indexHTTPRouteByGateway function, which is used in the Gateway reconciler
// to filter a HTTPRoute List operation so that it only lists HTTPRoutes that have the Gateway
// under reconciliation as a parent. In order to be able to use the indexer in the tests for
// the Gateway reconciler, it cannot use a client.Client, as the indexer functions are used to
// build the fake Client.
package indexers
