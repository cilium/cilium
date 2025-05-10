// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package testutils

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/node/addressing"
)

var (
	TestLbsA = map[string]string{
		"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "ns",
		"k8s:io.cilium.k8s.policy.cluster":                               "",
		"k8s:io.kubernetes.pod.namespace":                                "ns",
		"key-a":                                                          "val-1"}
	TestLbsB = map[string]string{
		"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "ns",
		"k8s:io.cilium.k8s.policy.cluster":                               "",
		"k8s:io.kubernetes.pod.namespace":                                "ns",
		"key-b":                                                          "val-2"}
	TestLbsC = map[string]string{
		"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name": "ns",
		"k8s:io.cilium.k8s.policy.cluster":                               "",
		"k8s:io.kubernetes.pod.namespace":                                "ns",
		"key-c":                                                          "val-3"}
)

var (
	NodeIPs = map[string]string{
		"node1": "10.0.0.0",
		"node2": "10.0.0.1",
		"node3": "10.0.0.2",
	}
)

func CreateManagerEndpoint(name string, identity int64, node string) capi_v2a1.CoreCiliumEndpoint {
	return capi_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: identity,
		Networking: &v2.EndpointNetworking{
			NodeIP: NodeIPs[node],
		},
	}
}

func CreateStoreEndpoint(name string, namespace string, identity int64) *v2.CiliumEndpoint {
	return &v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{
				ID: identity,
			},
			Networking: &v2.EndpointNetworking{},
		},
	}
}

func CreateStoreNode(name string) *v2.CiliumNode {
	return &v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
		Spec: v2.NodeSpec{
			Addresses: []v2.NodeAddress{
				{
					Type: addressing.AddressType("InternalIP"),
					IP:   NodeIPs[name],
				},
			},
			Encryption: v2.EncryptionSpec{
				Key: 0,
			},
		},
	}
}

func CreateStoreEndpointSlice(name string, namespace string, endpoints []capi_v2a1.CoreCiliumEndpoint) *capi_v2a1.CiliumEndpointSlice {
	return &capi_v2a1.CiliumEndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
		Namespace: namespace,
		Endpoints: endpoints,
	}
}

func CreateCESWithIDs(cesName string, ids []int64) *capi_v2a1.CiliumEndpointSlice {
	ces := &capi_v2a1.CiliumEndpointSlice{ObjectMeta: meta_v1.ObjectMeta{Name: cesName}}
	for _, id := range ids {
		cep := capi_v2a1.CoreCiliumEndpoint{IdentityID: id}
		ces.Endpoints = append(ces.Endpoints, cep)
	}
	return ces
}
