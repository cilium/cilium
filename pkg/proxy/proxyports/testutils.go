// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

type MockDatapathUpdater struct{}

func (m *MockDatapathUpdater) InstallProxyRules(proxyPort uint16, name string) {
}

func (m *MockDatapathUpdater) GetProxyPorts() map[string]uint16 {
	return nil
}

func proxyPortsForTest(t *testing.T) (*ProxyPorts, func()) {
	mockDatapathUpdater := &MockDatapathUpdater{}
	p := NewProxyPorts(hivetest.Logger(t), 10000, 20000, mockDatapathUpdater)
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
