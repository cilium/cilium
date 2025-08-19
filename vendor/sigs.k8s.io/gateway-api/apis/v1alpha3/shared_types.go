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

package v1alpha3

import v1 "sigs.k8s.io/gateway-api/apis/v1"

// CommonRouteSpec defines the common attributes that all Routes MUST include
// within their spec.
// +k8s:deepcopy-gen=false
type CommonRouteSpec = v1.CommonRouteSpec

// BackendRef defines how a Route should forward a request to a Kubernetes
// resource.
//
// Note that when a namespace different than the local namespace is specified, a
// ReferenceGrant object is required in the referent namespace to allow that
// namespace's owner to accept the reference. See the ReferenceGrant
// documentation for details.
// +k8s:deepcopy-gen=false
type BackendRef = v1.BackendRef

// RouteStatus defines the common attributes that all Routes MUST include within
// their status.
// +k8s:deepcopy-gen=false
type RouteStatus = v1.RouteStatus

// Hostname is the fully qualified domain name of a network host. This matches
// the RFC 1123 definition of a hostname with 2 notable exceptions:
//
//  1. IPs are not allowed.
//  2. A hostname may be prefixed with a wildcard label (`*.`). The wildcard
//     label must appear by itself as the first label.
//
// Hostname can be "precise" which is a domain name without the terminating
// dot of a network host (e.g. "foo.example.com") or "wildcard", which is a
// domain name prefixed with a single wildcard label (e.g. `*.example.com`).
//
// Note that as per RFC1035 and RFC1123, a *label* must consist of lower case
// alphanumeric characters or '-', and must start and end with an alphanumeric
// character. No other punctuation is allowed.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type Hostname = v1.Hostname

// SectionName is the name of a section in a Kubernetes resource.
//
// In the following resources, SectionName is interpreted as the following:
//
// * Gateway: Listener name
// * HTTPRoute: HTTPRouteRule name
// * Service: Port name
//
// Section names can have a variety of forms, including RFC 1123 subdomains,
// RFC 1123 labels, or RFC 1035 labels.
//
// This validation is based off of the corresponding Kubernetes validation:
// https://github.com/kubernetes/apimachinery/blob/02cfb53916346d085a6c6c7c66f882e3c6b0eca6/pkg/util/validation/validation.go#L208
//
// Valid values include:
//
// * "example"
// * "foo-example"
// * "example.com"
// * "foo.example.com"
//
// Invalid values include:
//
// * "example.com/bar" - "/" is an invalid character
//
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
type SectionName = v1.SectionName
