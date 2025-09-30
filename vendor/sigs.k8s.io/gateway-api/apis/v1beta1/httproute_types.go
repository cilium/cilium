/*
Copyright 2020 The Kubernetes Authors.

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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Hostnames",type=string,JSONPath=`.spec.hostnames`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HTTPRoute provides a way to route HTTP requests. This includes the capability
// to match requests by hostname, path, header, or query param. Filters can be
// used to specify additional processing steps. Backends specify where matching
// requests should be routed.
type HTTPRoute v1.HTTPRoute

// +kubebuilder:object:root=true

// HTTPRouteList contains a list of HTTPRoute.
type HTTPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRoute `json:"items"`
}

type HTTPRouteSpec = v1.HTTPRouteSpec

type HTTPRouteRule = v1.HTTPRouteRule

type PathMatchType = v1.PathMatchType

type HTTPPathMatch = v1.HTTPPathMatch

type HeaderMatchType = v1.HeaderMatchType

type HTTPHeaderName = v1.HTTPHeaderName

type HTTPHeaderMatch = v1.HTTPHeaderMatch

type QueryParamMatchType = v1.QueryParamMatchType

type HTTPQueryParamMatch = v1.HTTPQueryParamMatch

type HTTPMethod = v1.HTTPMethod

type HTTPRouteMatch = v1.HTTPRouteMatch

type HTTPRouteFilter = v1.HTTPRouteFilter

type HTTPRouteFilterType = v1.HTTPRouteFilterType

type HTTPRouteTimeouts = v1.HTTPRouteTimeouts

type HTTPHeader = v1.HTTPHeader

type HTTPHeaderFilter = v1.HTTPHeaderFilter

type HTTPPathModifierType = v1.HTTPPathModifierType

type HTTPPathModifier = v1.HTTPPathModifier

type HTTPRequestRedirectFilter = v1.HTTPRequestRedirectFilter

type HTTPURLRewriteFilter = v1.HTTPURLRewriteFilter

type HTTPRequestMirrorFilter = v1.HTTPRequestMirrorFilter

type HTTPBackendRef = v1.HTTPBackendRef

type HTTPRouteStatus = v1.HTTPRouteStatus
