/*
Copyright 2025 The Kubernetes Authors.

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

package resources

import "k8s.io/apimachinery/pkg/types"

const (
	AppBackendNamespace  = "inference-conformance-app-backend"
	InfraNamespace       = "inference-conformance-infra"
	PrimaryGatewayName   = "conformance-primary"
	SecondaryGatewayName = "conformance-secondary"

	PrimaryInferencePoolName         = "primary-inference-pool"
	SecondaryInferencePoolName       = "secondary-inference-pool"
	AppProtocolHTTPInferencePoolName = "appprotocol-http-inference-pool"
	AppProtocolH2CInferencePoolName  = "appprotocol-h2c-inference-pool"

	PrimaryModelServerAppLabel           = "primary-inference-model-server"
	SecondaryModelServerAppLabel         = "secondary-inference-model-server"
	AppProtocolModelServerAppLabel       = "appprotocol-inference-model-server"
	PrimaryModelServerDeploymentName     = "primary-inference-model-server-deployment"
	SecondaryModelServerDeploymentName   = "secondary-inference-model-server-deployment"
	AppProtocolModelServerDeploymentName = "appprotocol-inference-model-server-deployment"

	ModelServerPodReplicas    = 3
	EndPointPickerPodReplicas = 1
)

var (
	PrimaryGatewayNN   = types.NamespacedName{Name: PrimaryGatewayName, Namespace: InfraNamespace}
	SecondaryGatewayNN = types.NamespacedName{Name: SecondaryGatewayName, Namespace: InfraNamespace}

	PrimaryInferencePoolNN         = types.NamespacedName{Name: PrimaryInferencePoolName, Namespace: AppBackendNamespace}
	SecondaryInferencePoolNN       = types.NamespacedName{Name: SecondaryInferencePoolName, Namespace: AppBackendNamespace}
	AppProtocolHTTPInferencePoolNN = types.NamespacedName{Name: AppProtocolHTTPInferencePoolName, Namespace: AppBackendNamespace}
	AppProtocolH2CInferencePoolNN  = types.NamespacedName{Name: AppProtocolH2CInferencePoolName, Namespace: AppBackendNamespace}

	PrimaryEppDeploymentNN   = types.NamespacedName{Name: "primary-app-endpoint-picker", Namespace: AppBackendNamespace}
	SecondaryEppDeploymentNN = types.NamespacedName{Name: "secondary-app-endpoint-picker", Namespace: AppBackendNamespace}

	PrimaryEppServiceNN   = types.NamespacedName{Name: "primary-endpoint-picker-svc", Namespace: AppBackendNamespace}
	SecondaryEppServiceNN = types.NamespacedName{Name: "secondary-endpoint-picker-svc", Namespace: AppBackendNamespace}
)
