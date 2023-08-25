// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"fmt"

	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type monitorAgentLogRecordNotifier struct {
	monitorAgent monitoragent.Agent
}

func NewMonitorAgentLogRecordNotifier(monitorAgent monitoragent.Agent) LogRecordNotifier {
	return &monitorAgentLogRecordNotifier{monitorAgent: monitorAgent}
}

func (m *monitorAgentLogRecordNotifier) NewProxyLogRecord(l *LogRecord) error {
	if err := m.monitorAgent.SendEvent(monitorAPI.MessageTypeAccessLog, l.LogRecord); err != nil {
		return fmt.Errorf("failed to send log record to monitor agent: %w", err)
	}
	return nil
}
