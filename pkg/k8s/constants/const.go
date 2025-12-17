// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package constants

const (
	// EnvNodeNameSpec is the environment label used by Kubernetes to
	// specify the node's name.
	EnvNodeNameSpec = "K8S_NODE_NAME"
)

const (
	// ServiceLBClassNodeIPAM indicates if a Service VIP should be allocated
	// with Node-IPAM. This can be carried in Service.Spec.LoadBalancerClass
	// (placed in k8s/constants to avoid creating another pkg just for this!)
	ServiceLBClassNodeIPAM = "io.cilium/node"
)
