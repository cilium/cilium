// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

type MockIPTablesManager struct{}

var _ datapath.IptablesManager = &MockIPTablesManager{}

func (m *MockIPTablesManager) InstallNoTrackRules(ip netip.Addr, port uint16) {}

func (m *MockIPTablesManager) RemoveNoTrackRules(ip netip.Addr, port uint16) {}

func (m *MockIPTablesManager) SupportsOriginalSourceAddr() bool {
	return false
}

func (m *MockIPTablesManager) InstallProxyRules(proxyPort uint16, name string) {}

func (m *MockIPTablesManager) GetProxyPorts() map[string]uint16 {
	return nil
}

func proxyPortsForTest(t *testing.T) (*ProxyPorts, func()) {
	mockIPTablesManager := &MockIPTablesManager{}
	config := ProxyPortsConfig{
		ProxyPortrangeMin:          10000,
		ProxyPortrangeMax:          20000,
		RestoredProxyPortsAgeLimit: 0,
	}

	p := NewProxyPorts(hivetest.Logger(t), config, mockIPTablesManager)
	triggerDone := make(chan struct{})
	p.Trigger, _ = trigger.NewTrigger(trigger.Parameters{
		MinInterval:  10 * time.Millisecond,
		TriggerFunc:  func(reasons []string) {},
		ShutdownFunc: func() { close(triggerDone) },
	})
	return p, func() {
		p.Trigger.Shutdown()
		<-triggerDone
	}
}
