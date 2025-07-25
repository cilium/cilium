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

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ServiceImportPluralName is the plural name of ServiceImport
	ServiceImportPluralName = "serviceimports"
	// ServiceImportKindName is the kind name of ServiceImport
	ServiceImportKindName = "ServiceImport"
	// ServiceImportFullName is the full name of ServiceImport
	ServiceImportFullName = ServiceImportPluralName + "." + GroupName
)

// ServiceImportVersionedName is the versioned name of ServiceImport
var ServiceImportVersionedName = ServiceImportKindName + "/" + GroupVersion.Version

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName={svcim,svcimport}

// ServiceImport describes a service imported from clusters in a ClusterSet.
type ServiceImport struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// spec defines the behavior of a ServiceImport.
	// +optional
	Spec ServiceImportSpec `json:"spec,omitempty"`
	// status contains information about the exported services that form
	// the multi-cluster service referenced by this ServiceImport.
	// +optional
	Status ServiceImportStatus `json:"status,omitempty"`
}

// ServiceImportType designates the type of a ServiceImport
type ServiceImportType string

const (
	// ClusterSetIP are only accessible via the ClusterSet IP.
	ClusterSetIP ServiceImportType = "ClusterSetIP"
	// Headless services allow backend pods to be addressed directly.
	Headless ServiceImportType = "Headless"
)

// ServiceImportSpec describes an imported service and the information necessary to consume it.
type ServiceImportSpec struct {
	// +listType=atomic
	Ports []ServicePort `json:"ports"`
	// ip will be used as the VIP for this service when type is ClusterSetIP.
	// +kubebuilder:validation:MaxItems:=2
	// +optional
	IPs []string `json:"ips,omitempty"`
	// type defines the type of this service.
	// Must be ClusterSetIP or Headless.
	// +kubebuilder:validation:Enum=ClusterSetIP;Headless
	Type ServiceImportType `json:"type"`
	// Supports "ClientIP" and "None". Used to maintain session affinity.
	// Enable client IP based session affinity.
	// Must be ClientIP or None.
	// Defaults to None.
	// Ignored when type is Headless
	// More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
	// +optional
	SessionAffinity v1.ServiceAffinity `json:"sessionAffinity,omitempty"`
	// sessionAffinityConfig contains session affinity configuration.
	// +optional
	SessionAffinityConfig *v1.SessionAffinityConfig `json:"sessionAffinityConfig,omitempty"`
}

// ServicePort represents the port on which the service is exposed
type ServicePort struct {
	// The name of this port within the service. This must be a DNS_LABEL.
	// All ports within a ServiceSpec must have unique names. When considering
	// the endpoints for a Service, this must match the 'name' field in the
	// EndpointPort.
	// Optional if only one ServicePort is defined on this service.
	// +optional
	Name string `json:"name,omitempty"`

	// The IP protocol for this port. Supports "TCP", "UDP", and "SCTP".
	// Default is TCP.
	// +optional
	Protocol v1.Protocol `json:"protocol,omitempty"`

	// The application protocol for this port.
	// This is used as a hint for implementations to offer richer behavior for protocols that they understand.
	// This field follows standard Kubernetes label syntax.
	// Valid values are either:
	//
	// * Un-prefixed protocol names - reserved for IANA standard service names (as per
	// RFC-6335 and https://www.iana.org/assignments/service-names).
	//
	// * Kubernetes-defined prefixed names:
	//   * 'kubernetes.io/h2c' - HTTP/2 over cleartext as described in https://www.rfc-editor.org/rfc/rfc7540
	//
	// * Other protocols should use implementation-defined prefixed names such as
	// mycompany.com/my-custom-protocol.
	// Field can be enabled with ServiceAppProtocol feature gate.
	// +optional
	AppProtocol *string `json:"appProtocol,omitempty"`

	// The port that will be exposed by this service.
	Port int32 `json:"port"`
}

// ServiceImportStatus describes derived state of an imported service.
type ServiceImportStatus struct {
	// clusters is the list of exporting clusters from which this service
	// was derived.
	// +optional
	// +patchStrategy=merge
	// +patchMergeKey=cluster
	// +listType=map
	// +listMapKey=cluster
	Clusters []ClusterStatus `json:"clusters,omitempty"`
}

// ClusterStatus contains service configuration mapped to a specific source cluster
type ClusterStatus struct {
	// cluster is the name of the exporting cluster. Must be a valid RFC-1123 DNS
	// label.
	Cluster string `json:"cluster"`
}

// +kubebuilder:object:root=true

// ServiceImportList represents a list of endpoint slices
type ServiceImportList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of endpoint slices
	// +listType=set
	Items []ServiceImport `json:"items"`
}
