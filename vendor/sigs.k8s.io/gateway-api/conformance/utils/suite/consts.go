/*
Copyright The Kubernetes Authors.

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

// Conformance suite shared constants
const (
	// InfrastructureNamespace is the main conformance infra namespace for Gateways and core resources
	InfrastructureNamespace = "gateway-conformance-infra"
	// AppBackendNamespace is the namespace for app backends
	AppBackendNamespace = "gateway-conformance-app-backend"
	// WebBackendNamespace is the namespace for web backends
	WebBackendNamespace = "gateway-conformance-web-backend"
	// MeshNamespace is the namespace for mesh conformance tests
	MeshNamespace = "gateway-conformance-mesh"
	// MeshConsumerNamespace is the namespace for mesh consumer in conformance tests
	MeshConsumerNamespace = "gateway-conformance-mesh-consumer"
	// InfrastructureGatewayName is the default Gateway name in the infra namespace
	InfrastructureGatewayName = "gateway-conformance-infra-test"

	// InfraBackendServiceNameV1 is the name of the v1 infra backend service
	InfraBackendServiceNameV1 = "infra-backend-v1"
	// InfraBackendServiceNameV2 is the name of the v2 infra backend service
	InfraBackendServiceNameV2 = "infra-backend-v2"
	// InfraBackendServiceNameV3 is the name of the v3 infra backend service
	InfraBackendServiceNameV3 = "infra-backend-v3"

	// undefinedKeyword is set in the ConformanceReport "GatewayAPIVersion" and
	// "GatewayAPIChannel" fields in case it's not possible to figure out the actual
	// values in the cluster, due to multiple versions of CRDs installed.
	UndefinedKeyword = "UNDEFINED"
)
