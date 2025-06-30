// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func (m Metrics) AddLRPConfig(_ loadbalancer.ServiceName) {
	m.NPLRPIngested.WithLabelValues(actionAdd).Inc()
}

func (m Metrics) DelLRPConfig(_ loadbalancer.ServiceName) {
	m.NPLRPIngested.WithLabelValues(actionDel).Inc()
}

func (m Metrics) AddService(svc *loadbalancer.Service) {
	if svc != nil && svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		m.ACLBInternalTrafficPolicyIngested.WithLabelValues(actionAdd).Inc()
	}
}

func (m Metrics) DelService(svc *loadbalancer.Service) {
	if svc != nil && svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		m.ACLBInternalTrafficPolicyIngested.WithLabelValues(actionDel).Inc()
	}
}

func (m Metrics) AddCEC() {
	m.ACLBCiliumEnvoyConfigIngested.WithLabelValues(actionAdd).Inc()
}

func (m Metrics) DelCEC() {
	m.ACLBCiliumEnvoyConfigIngested.WithLabelValues(actionDel).Inc()
}

func (m Metrics) AddCCEC() {
	m.ACLBCiliumClusterwideEnvoyConfigIngested.WithLabelValues(actionAdd).Inc()
}

func (m Metrics) DelCCEC() {
	m.ACLBCiliumClusterwideEnvoyConfigIngested.WithLabelValues(actionDel).Inc()
}

func (m Metrics) AddCNP(_ *v2.CiliumNetworkPolicy) {
	m.NPCNPIngested.WithLabelValues(actionAdd).Inc()
}

func (m Metrics) DelCNP(_ *v2.CiliumNetworkPolicy) {
	m.NPCNPIngested.WithLabelValues(actionDel).Inc()
}

func (m Metrics) AddCCNP(_ *v2.CiliumNetworkPolicy) {
	m.NPCCNPIngested.WithLabelValues(actionAdd).Inc()
}

func (m Metrics) DelCCNP(_ *v2.CiliumNetworkPolicy) {
	m.NPCCNPIngested.WithLabelValues(actionDel).Inc()
}

func (m Metrics) AddClusterMeshConfig(clusterMeshMode string, maxConnectedClusters string) {
	m.ACLBClusterMeshEnabled.WithLabelValues(clusterMeshMode, maxConnectedClusters).Inc()
}

func (m Metrics) DelClusterMeshConfig(clusterMeshMode string, maxConnectedClusters string) {
	m.ACLBClusterMeshEnabled.WithLabelValues(clusterMeshMode, maxConnectedClusters).Dec()
}
