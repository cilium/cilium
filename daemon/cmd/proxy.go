// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

// NewProxyLogRecord is invoked by the proxy accesslog on each new access log entry
func (d *Daemon) NewProxyLogRecord(l *logger.LogRecord) error {
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAccessLog, l.LogRecord)
}
