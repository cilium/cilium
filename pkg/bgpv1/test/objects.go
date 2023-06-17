// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	// uid is static ID used in tests
	uid = types.UID("610a54cf-e0e5-4dc6-ace9-0e6ca9a4aaae")
)

// policyConfig data used to create CiliumBGPPeeringPolicy
type policyConfig struct {
	nodeSelector   map[string]slim_meta_v1.MatchLabelsValue
	virtualRouters []v2alpha1.CiliumBGPVirtualRouter
}

// newPolicyObj created CiliumBGPPeeringPolicy based on passed policy config
func newPolicyObj(conf policyConfig) v2alpha1.CiliumBGPPeeringPolicy {
	policyObj := v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "policy-1",
			UID:               uid,
			CreationTimestamp: metav1.Now(),
		},
	}

	if conf.nodeSelector != nil {
		policyObj.Spec.NodeSelector = &slim_meta_v1.LabelSelector{
			MatchLabels: conf.nodeSelector,
		}
	}

	if conf.virtualRouters != nil {
		policyObj.Spec.VirtualRouters = conf.virtualRouters
	}

	return policyObj
}

// nodeConfig data used to create/update node object
type nodeConfig struct {
	labels      map[string]string
	annotations map[string]string
	podCIDRs    []string
}

// newNodeObj creates new corev1.Node object based on passed config
func newNodeObj(conf nodeConfig) slim_core_v1.Node {
	nodeObj := slim_core_v1.Node{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:        "base-node",
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
	}

	if conf.labels != nil {
		nodeObj.ObjectMeta.Labels = conf.labels
	}

	if conf.annotations != nil {
		nodeObj.ObjectMeta.Annotations = conf.annotations
	}

	if conf.podCIDRs != nil {
		nodeObj.Spec.PodCIDRs = conf.podCIDRs
	}

	return nodeObj
}

// lbSrvConfig contains lb service configuration data
type lbSrvConfig struct {
	name      string
	ingressIP string
}

// newLBServiceObj creates slim_core_v1.Service object based on lbSrvConfig
func newLBServiceObj(conf lbSrvConfig) slim_core_v1.Service {
	srvObj := slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name: conf.name,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}

	srvObj.Status = slim_core_v1.ServiceStatus{
		LoadBalancer: slim_core_v1.LoadBalancerStatus{
			Ingress: []slim_core_v1.LoadBalancerIngress{{IP: conf.ingressIP}},
		},
	}

	return srvObj
}
