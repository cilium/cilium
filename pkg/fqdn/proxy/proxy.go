// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

type DNSProxier interface {
	GetRules(*versioned.VersionHandle, uint16) (restore.DNSRules, error)
	RemoveRestoredRules(uint16)
	UpdateAllowed(endpointID uint64, destPort restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error)
	GetBindPort() uint16
	RestoreRules(op *endpoint.Endpoint)
	Cleanup()

	Listen(port uint16) error
}

var _ DNSProxier = (*MockFQDNProxy)(nil)

type MockFQDNProxy struct{}

func (m MockFQDNProxy) GetRules(*versioned.VersionHandle, uint16) (restore.DNSRules, error) {
	return nil, nil
}

func (m MockFQDNProxy) RemoveRestoredRules(u uint16) {
}

func (m MockFQDNProxy) UpdateAllowed(endpointID uint64, destPort restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error) {
	return nil, nil
}

func (m MockFQDNProxy) GetBindPort() uint16 {
	return 0
}

func (m MockFQDNProxy) RestoreRules(op *endpoint.Endpoint) {
}

func (m MockFQDNProxy) Cleanup() {
}

func (m MockFQDNProxy) Listen(uint16) error {
	return nil
}
