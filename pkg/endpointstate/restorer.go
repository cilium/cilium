// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

// EndpointsRestored is an empty type used for promise.Promise.
// Waiting on that promise blocks the caller until either the context is
// cancelled or all the endpoints have been restored from a previous run.
type EndpointsRestored struct{}

// InitialPoliciesComputed is an empty type used for promise.Promise.
// Waiting on that promise blocks the caller until either the context is
// cancelled or initial policies of all restored endpoints have been computed.
type InitialPoliciesComputed struct{}
