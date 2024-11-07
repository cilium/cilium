/*
Copyright 2024 The Kubernetes Authors.

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

package features

import "k8s.io/apimachinery/pkg/util/sets"

// -----------------------------------------------------------------------------
// Features - Gateway Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for Gateway.
	// Opting out of this is allowed only for GAMMA-only implementations
	SupportGateway FeatureName = "Gateway"
)

// GatewayFeature contains metadata for the Gateway feature.
var GatewayFeature = Feature{
	Name:    SupportGateway,
	Channel: FeatureChannelStandard,
}

// GatewayCoreFeatures are the features that are required to be conformant with
// the Gateway resource.
var GatewayCoreFeatures = sets.New(
	GatewayFeature,
)

// -----------------------------------------------------------------------------
// Features - Gateway Conformance (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates that the Gateway can also use port 8080
	SupportGatewayPort8080 FeatureName = "GatewayPort8080"

	// SupportGatewayStaticAddresses option indicates that the Gateway is capable
	// of allocating pre-determined addresses, rather than dynamically having
	// addresses allocated for it.
	SupportGatewayStaticAddresses FeatureName = "GatewayStaticAddresses"

	// SupportGatewayHTTPListenerIsolation option indicates support for the isolation
	// of HTTP listeners.
	SupportGatewayHTTPListenerIsolation FeatureName = "GatewayHTTPListenerIsolation"

	// SupportGatewayInfrastructureAnnotations option indicates support for
	// spec.infrastructure.annotations and spec.infrastrucutre.labels
	SupportGatewayInfrastructurePropagation FeatureName = "GatewayInfrastructurePropagation"
)

var (
	// GatewayPort8080Feature contains metadata for the GatewayPort8080 feature.
	GatewayPort8080Feature = Feature{
		Name:    SupportGatewayPort8080,
		Channel: FeatureChannelStandard,
	}
	// GatewayStaticAddressesFeature contains metadata for the GatewayStaticAddresses feature.
	GatewayStaticAddressesFeature = Feature{
		Name:    SupportGatewayStaticAddresses,
		Channel: FeatureChannelStandard,
	}
	// GatewayHTTPListenerIsolationFeature contains metadata for the GatewayHTTPListenerIsolation feature.
	GatewayHTTPListenerIsolationFeature = Feature{
		Name:    SupportGatewayHTTPListenerIsolation,
		Channel: FeatureChannelStandard,
	}
	// GatewayInfrastructurePropagationFeature contains metadata for the GatewayInfrastructurePropagation feature.
	GatewayInfrastructurePropagationFeature = Feature{
		Name:    SupportGatewayInfrastructurePropagation,
		Channel: FeatureChannelExperimental,
	}
)

// GatewayExtendedFeatures are extra generic features that implementations may
// choose to support as an opt-in. This does not include any Core Features.
var GatewayExtendedFeatures = sets.New(
	GatewayPort8080Feature,
	GatewayStaticAddressesFeature,
	GatewayHTTPListenerIsolationFeature,
	GatewayInfrastructurePropagationFeature,
)
