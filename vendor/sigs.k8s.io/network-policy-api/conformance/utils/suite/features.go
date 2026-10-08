/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package suite

import "k8s.io/apimachinery/pkg/util/sets"

// -----------------------------------------------------------------------------
// Features - Types
// -----------------------------------------------------------------------------

// SupportedFeature allows opting in to additional conformance tests at an
// individual feature granularity.
type SupportedFeature string

// -----------------------------------------------------------------------------
// Features - Core
// -----------------------------------------------------------------------------

const (
	// This option indicates support for ANP (standard conformance).
	SupportClusterNetworkPolicy SupportedFeature = "ClusterNetworkPolicy"
)

// StandardFeatures are the features that are required to be conformant with
// the Core API features (e.g. all fields in the API except for NamedPorts).
var StandardFeatures = sets.New(
	SupportClusterNetworkPolicy,
)

// -----------------------------------------------------------------------------
// Features - Experimental
// -----------------------------------------------------------------------------

const (
	// This option indicates ClusterNetworkPolicy's NamedPorts, EgressNodePeers
	// fall under the extended test conformance.
	SupportClusterNetworkPolicyNamedPorts      SupportedFeature = "ClusterNetworkPolicyNamedPorts"
	SupportClusterNetworkPolicyEgressNodePeers SupportedFeature = "ClusterNetworkPolicyEgressNodePeers"
)

// ExperimentalFeatures are newer, unstable features that are not part of the standard channel.
// If implementations want to use these features, they can use the experimental CR to leverage them.
var ExperimentalFeatures = sets.New(
	SupportClusterNetworkPolicyNamedPorts,
	SupportClusterNetworkPolicyEgressNodePeers,
).Insert(StandardFeatures.UnsortedList()...)

// -----------------------------------------------------------------------------
// Features - Compilations
// -----------------------------------------------------------------------------

// AllFeatures contains all the supported features and can be used to run all
// conformance tests with `all-features` flag.
//
// NOTE: as new feature sets are added they should be inserted into this set.
var AllFeatures = sets.New[SupportedFeature]().
	Insert(ExperimentalFeatures.UnsortedList()...)
