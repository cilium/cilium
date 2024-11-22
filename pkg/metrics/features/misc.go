// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

func (m Metrics) AddLRPConfig(_ *redirectpolicy.LRPConfig) {
	if m.NPLRPIngested.Get() == 0 {
		m.NPLRPIngested.Inc()
	}
	m.NPLRPPresent.Inc()
}

func (m Metrics) DelLRPConfig(_ *redirectpolicy.LRPConfig) {
	m.NPLRPPresent.Dec()
}

func (m Metrics) AddService(svc *k8s.Service) {
	if svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		if m.ACLBInternalTrafficPolicyIngested.Get() == 0 {
			m.ACLBInternalTrafficPolicyIngested.Inc()
		}
		m.ACLBInternalTrafficPolicyPresent.Inc()
	}
}

func (m Metrics) DelService(svc *k8s.Service) {
	if svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		m.ACLBInternalTrafficPolicyPresent.Dec()
	}
}

func (m Metrics) AddCEC(_ *v2.CiliumEnvoyConfigSpec) {
	if m.ACLBCiliumEnvoyConfigIngested.Get() == 0 {
		m.ACLBCiliumEnvoyConfigIngested.Inc()
	}
	m.ACLBCiliumEnvoyConfigPresent.Inc()
}

func (m Metrics) DelCEC(_ *v2.CiliumEnvoyConfigSpec) {
	m.ACLBCiliumEnvoyConfigPresent.Dec()
}

func (m Metrics) AddCCEC(_ *v2.CiliumEnvoyConfigSpec) {
	if m.ACLBCiliumClusterwideEnvoyConfigIngested.Get() == 0 {
		m.ACLBCiliumClusterwideEnvoyConfigIngested.Inc()
	}
	m.ACLBCiliumClusterwideEnvoyConfigPresent.Inc()
}

func (m Metrics) DelCCEC(_ *v2.CiliumEnvoyConfigSpec) {
	m.ACLBCiliumClusterwideEnvoyConfigPresent.Dec()
}

func (m Metrics) AddCNP(_ *v2.CiliumNetworkPolicy) {
	if m.NPCNPIngested.Get() == 0 {
		m.NPCNPIngested.Inc()
	}
	m.NPCNPPresent.Inc()
}

func (m Metrics) DelCNP(_ *v2.CiliumNetworkPolicy) {
	m.NPCNPPresent.Dec()
}

func (m Metrics) AddCCNP(_ *v2.CiliumNetworkPolicy) {
	if m.NPCCNPIngested.Get() == 0 {
		m.NPCCNPIngested.Inc()
	}
	m.NPCCNPPresent.Inc()
}

func (m Metrics) DelCCNP(_ *v2.CiliumNetworkPolicy) {
	m.NPCCNPPresent.Dec()
}
