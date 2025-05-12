// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

type ProxyUpdaterMock struct {
	Id            uint64
	Ipv4          string
	Ipv6          string
	VersionHandle *versioned.VersionHandle
}

func (m *ProxyUpdaterMock) GetPolicyNames() []string {
	var res []string
	if len(m.Ipv4) != 0 {
		res = append(res, m.Ipv4)
	}

	if len(m.Ipv6) != 0 {
		res = append(res, m.Ipv6)
	}
	return res
}

func (m *ProxyUpdaterMock) GetID() uint64 { return m.Id }

func (m *ProxyUpdaterMock) GetIPv4Address() string { return m.Ipv4 }

func (m *ProxyUpdaterMock) GetIPv6Address() string { return m.Ipv6 }

func (m *ProxyUpdaterMock) GetNamedPort(bool, string, u8proto.U8proto) uint16 { return 0 }

func (m *ProxyUpdaterMock) OnProxyPolicyUpdate(policyRevision uint64) {}

func (m *ProxyUpdaterMock) UpdateProxyStatistics(proxyType, l4Protocol string, port, proxyPort uint16, ingress, request bool,
	verdict accesslog.FlowVerdict) {
}

func (m *ProxyUpdaterMock) OnDNSPolicyUpdateLocked(rules restore.DNSRules) {}

func (m *ProxyUpdaterMock) GetPolicyVersionHandle() *versioned.VersionHandle {
	return m.VersionHandle
}

func (m *ProxyUpdaterMock) GetListenerProxyPort(listener string) uint16 {
	return 0
}
