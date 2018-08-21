// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

type IngressIsolationPolicy string

const (
	// DefaultDeny denies all ingress traffic to pods in this namespace. Ingress means
	// any incoming traffic to pods, whether that be from other pods within this namespace
	// or any source outside of this namespace.
	DefaultDeny IngressIsolationPolicy = "DefaultDeny"
)

// NamespaceSpec is the standard namespace object, modified to include a new
// NamespaceNetworkPolicy field.
type NamespaceSpec struct {
	// This is a pointer so that it can be left undefined.
	NetworkPolicy *NamespaceNetworkPolicy `json:"networkPolicy,omitempty"`
}

type NamespaceNetworkPolicy struct {
	// Ingress configuration for this namespace.  This config is
	// applied to all pods within this namespace. For now, only
	// ingress is supported.  This field is optional - if not
	// defined, then the cluster default for ingress is applied.
	Ingress *NamespaceIngressPolicy `json:"ingress,omitempty"`
}

// NamespaceIngressPolicy is the configuration for ingress to pods within this
// namespace. For now, this only supports specifying an isolation policy.
type NamespaceIngressPolicy struct {
	// The isolation policy to apply to pods in this namespace.
	// Currently this field only supports "DefaultDeny", but could
	// be extended to support other policies in the future.  When set to DefaultDeny,
	// pods in this namespace are denied ingress traffic by default.  When not defined,
	// the cluster default ingress isolation policy is applied (currently allow all).
	Isolation *IngressIsolationPolicy `json:"isolation,omitempty"`
}
