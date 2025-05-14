// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"fmt"

	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type monitorAgentLogRecordNotifier struct {
	monitorAgent monitoragent.Agent
}

func newMonitorAgentLogRecordNotifier(monitorAgent monitoragent.Agent) LogRecordNotifier {
	return &monitorAgentLogRecordNotifier{monitorAgent: monitorAgent}
}

func (m *monitorAgentLogRecordNotifier) NewProxyLogRecord(l *LogRecord) error {
	// Note: important to pass the event as value
	if err := m.monitorAgent.SendEvent(monitorAPI.MessageTypeAccessLog, *l); err != nil {
		return fmt.Errorf("failed to send log record to monitor agent: %w", err)
	}
	return nil
}
