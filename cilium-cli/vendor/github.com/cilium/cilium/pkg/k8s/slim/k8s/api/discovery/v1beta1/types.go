// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2019 The Kubernetes Authors.

package v1beta1

import (
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.16
// +k8s:prerelease-lifecycle-gen:deprecated=1.21
// +k8s:prerelease-lifecycle-gen:removed=1.25
// +k8s:prerelease-lifecycle-gen:replacement=discovery.k8s.io,v1,EndpointSlice

// EndpointSlice represents a subset of the endpoints that implement a service.
// For a given service there may be multiple EndpointSlice objects, selected by
// labels, which must be joined to produce the full set of endpoints.
type EndpointSlice struct {
	slim_metav1.TypeMeta `json:",inline"`

	// Standard object's metadata.
	// +optional
	slim_metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// addressType specifies the type of address carried by this EndpointSlice.
	// All addresses in this slice must be the same type. This field is
	// immutable after creation. The following address types are currently
	// supported:
	// * IPv4: Represents an IPv4 Address.
	// * IPv6: Represents an IPv6 Address.
	// * FQDN: Represents a Fully Qualified Domain Name.
	AddressType AddressType `json:"addressType" protobuf:"bytes,4,rep,name=addressType"`

	// endpoints is a list of unique endpoints in this slice. Each slice may
	// include a maximum of 1000 endpoints.
	// +listType=atomic
	Endpoints []Endpoint `json:"endpoints" protobuf:"bytes,2,rep,name=endpoints"`

	// ports specifies the list of network ports exposed by each endpoint in
	// this slice. Each port must have a unique name. When ports is empty, it
	// indicates that there are no defined ports. When a port is defined with a
	// nil port value, it indicates "all ports". Each slice may include a
	// maximum of 100 ports.
	// +optional
	// +listType=atomic
	Ports []EndpointPort `json:"ports" protobuf:"bytes,3,rep,name=ports"`
}

// AddressType represents the type of address referred to by an endpoint.
type AddressType string

const (
	// AddressTypeIPv4 represents an IPv4 Address.
	AddressTypeIPv4 = AddressType(slim_corev1.IPv4Protocol)

	// AddressTypeIPv6 represents an IPv6 Address.
	AddressTypeIPv6 = AddressType(slim_corev1.IPv6Protocol)

	// AddressTypeFQDN represents a FQDN.
	AddressTypeFQDN = AddressType("FQDN")
)

// Endpoint represents a single logical "backend" implementing a service.
type Endpoint struct {
	// addresses of this endpoint. The contents of this field are interpreted
	// according to the corresponding EndpointSlice addressType field. Consumers
	// must handle different types of addresses in the context of their own
	// capabilities. This must contain at least one address but no more than
	// 100. These are all assumed to be fungible and clients may choose to only
	// use the first element. Refer to: https://issue.k8s.io/106267
	// +listType=set
	Addresses []string `json:"addresses" protobuf:"bytes,1,rep,name=addresses"`

	// conditions contains information about the current status of the endpoint.
	Conditions EndpointConditions `json:"conditions,omitempty" protobuf:"bytes,2,opt,name=conditions"`

	// topology contains arbitrary topology information associated with the
	// endpoint. These key/value pairs must conform with the label format.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
	// Topology may include a maximum of 16 key/value pairs. This includes, but
	// is not limited to the following well known keys:
	// * kubernetes.io/hostname: the value indicates the hostname of the node
	//   where the endpoint is located. This should match the corresponding
	//   node label.
	// * topology.kubernetes.io/zone: the value indicates the zone where the
	//   endpoint is located. This should match the corresponding node label.
	// * topology.kubernetes.io/region: the value indicates the region where the
	//   endpoint is located. This should match the corresponding node label.
	// This field is deprecated and will be removed in future api versions.
	// +optional
	Topology map[string]string `json:"topology,omitempty" protobuf:"bytes,5,opt,name=topology"`

	// nodeName represents the name of the Node hosting this endpoint. This can
	// be used to determine endpoints local to a Node.
	// +optional
	NodeName *string `json:"nodeName,omitempty" protobuf:"bytes,6,opt,name=nodeName"`
}

// EndpointConditions represents the current condition of an endpoint.
type EndpointConditions struct {
	// ready indicates that this endpoint is prepared to receive traffic,
	// according to whatever system is managing the endpoint. A nil value
	// indicates an unknown state. In most cases consumers should interpret this
	// unknown state as ready. For compatibility reasons, ready should never be
	// "true" for terminating endpoints.
	// +optional
	Ready *bool `json:"ready,omitempty" protobuf:"bytes,1,name=ready"`

	// serving is identical to ready except that it is set regardless of the
	// terminating state of endpoints. This condition should be set to true for
	// a ready endpoint that is terminating. If nil, consumers should defer to
	// the ready condition.
	// +optional
	Serving *bool `json:"serving,omitempty" protobuf:"bytes,2,name=serving"`

	// terminating indicates that this endpoint is terminating. A nil value
	// indicates an unknown state. Consumers should interpret this unknown state
	// to mean that the endpoint is not terminating.
	// +optional
	Terminating *bool `json:"terminating,omitempty" protobuf:"bytes,3,name=terminating"`
}

// EndpointHints provides hints describing how an endpoint should be consumed.
type EndpointHints struct {
	// forZones indicates the zone(s) this endpoint should be consumed by to
	// enable topology aware routing. May contain a maximum of 8 entries.
	// +listType=atomic
	ForZones []ForZone `json:"forZones,omitempty" protobuf:"bytes,1,name=forZones"`
}

// ForZone provides information about which zones should consume this endpoint.
type ForZone struct {
	// name represents the name of the zone.
	Name string `json:"name" protobuf:"bytes,1,name=name"`
}

// EndpointPort represents a Port used by an EndpointSlice
type EndpointPort struct {
	// name represents the name of this port. All ports in an EndpointSlice must have a unique name.
	// If the EndpointSlice is derived from a Kubernetes service, this corresponds to the Service.ports[].name.
	// Name must either be an empty string or pass DNS_LABEL validation:
	// * must be no more than 63 characters long.
	// * must consist of lower case alphanumeric characters or '-'.
	// * must start and end with an alphanumeric character.
	// Default is empty string.
	Name *string `json:"name,omitempty" protobuf:"bytes,1,name=name"`

	// protocol represents the IP protocol for this port.
	// Must be UDP, TCP, or SCTP.
	// Default is TCP.
	Protocol *slim_corev1.Protocol `json:"protocol,omitempty" protobuf:"bytes,2,name=protocol"`

	// port represents the port number of the endpoint.
	// If this is not specified, ports are not restricted and must be
	// interpreted in the context of the specific consumer.
	Port *int32 `json:"port,omitempty" protobuf:"bytes,3,opt,name=port"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.16
// +k8s:prerelease-lifecycle-gen:deprecated=1.21
// +k8s:prerelease-lifecycle-gen:removed=1.25
// +k8s:prerelease-lifecycle-gen:replacement=discovery.k8s.io,v1,EndpointSlice

// EndpointSliceList represents a list of endpoint slices
type EndpointSliceList struct {
	slim_metav1.TypeMeta `json:",inline"`

	// Standard list metadata.
	// +optional
	slim_metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// items is the list of endpoint slices
	Items []EndpointSlice `json:"items" protobuf:"bytes,2,rep,name=items"`
}
