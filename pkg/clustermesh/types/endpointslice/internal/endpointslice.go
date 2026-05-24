// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package internal

import slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"

// ClusterEndpointSlice is the definition of an EndpointSlice in a cluster.
// It is split out from the main ClusterEndpointSlice so generated
// protobuf Marshal/Unmarshal methods do not conflict with Marshal/Unmarshal
// from the Key interface that also perform zstd compression.
//
// WARNING - STABLE API: Any change to this structure must be done in a
// backwards compatible way.
type ClusterEndpointSlice struct {
	Cluster   string `json:"cluster" protobuf:"bytes,1,name=cluster"`
	ClusterID uint32 `json:"clusterID" protobuf:"varint,2,name=clusterID"`

	Namespace string `json:"namespace" protobuf:"bytes,3,name=namespace"`
	Name      string `json:"name" protobuf:"bytes,4,name=name"`

	Labels      map[string]string `json:"labels,omitempty" protobuf:"bytes,5,rep,name=labels"`
	Annotations map[string]string `json:"annotations,omitempty" protobuf:"bytes,6,rep,name=annotations"`

	AddressType slim_discovery_v1.AddressType    `json:"addressType" protobuf:"bytes,7,name=addressType"`
	Endpoints   []slim_discovery_v1.Endpoint     `json:"endpoints" protobuf:"bytes,8,rep,name=endpoints"`
	Ports       []slim_discovery_v1.EndpointPort `json:"ports" protobuf:"bytes,9,rep,name=ports"`
}
