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

package v1

// Well-known labels for generated resources (Service, Deployment, etc.) when
// implementing a Gateway in-cluster. These labels and the recommended naming format can be used to
// attach resources to those workloads.
// Reference for further details: https://github.com/kubernetes-sigs/gateway-api/blob/main/geps/gep-1762/index.md
const (
	// All generated resources must include a label set to the name of the
	// Gateway resource.
	GatewayNameLabelKey = GroupName + "/gateway-name"
	// All generated resources should include a label set to the name of the
	// GatewayClass resource.
	GatewayClassNameLabelKey = GroupName + "/gateway-class-name"
)
