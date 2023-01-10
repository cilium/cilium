// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
)

type DNSProxier interface {
	GetRules(uint16) (restore.DNSRules, error)
	RemoveRestoredRules(uint16)
	UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error
	GetBindPort() uint16
	SetRejectReply(string)
	RestoreRules(op *endpoint.Endpoint)
	Cleanup()
}

type MockFQDNProxy struct{}

func (m MockFQDNProxy) GetRules(u uint16) (restore.DNSRules, error) {
	return nil, nil
}

func (m MockFQDNProxy) RemoveRestoredRules(u uint16) {
	return
}

func (m MockFQDNProxy) UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error {
	return nil
}

func (m MockFQDNProxy) GetBindPort() uint16 {
	return 0
}

func (m MockFQDNProxy) SetRejectReply(s string) {
	return
}

func (m MockFQDNProxy) RestoreRules(op *endpoint.Endpoint) {
	return
}

func (m MockFQDNProxy) Cleanup() {
	return
}
