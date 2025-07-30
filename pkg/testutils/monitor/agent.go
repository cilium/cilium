// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testmonitor

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
)

type TestMonitorAgent struct{}

func (*TestMonitorAgent) AttachToEventsMap(nPages int) error                       { return nil }
func (*TestMonitorAgent) SendEvent(typ int, event any) error                       { return nil }
func (*TestMonitorAgent) RegisterNewListener(newListener listener.MonitorListener) {}
func (*TestMonitorAgent) RemoveListener(ml listener.MonitorListener)               {}
func (*TestMonitorAgent) RegisterNewConsumer(newConsumer consumer.MonitorConsumer) {}
func (*TestMonitorAgent) RemoveConsumer(mc consumer.MonitorConsumer)               {}
func (*TestMonitorAgent) State() *models.MonitorStatus                             { return nil }
