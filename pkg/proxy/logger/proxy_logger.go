// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"log/slog"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/option"
)

type ProxyAccessLogger interface {
	// Log logs the given log record to the flow log (if flow debug logging is enabled)
	// and sends it of to the monitor agent via notifier.
	Log(lr *LogRecord)
}

type proxyAccessLogger struct {
	logger *slog.Logger

	notifier LogRecordNotifier
	metadata []string
}

// LogRecordNotifier is the interface to implement LogRecord notifications.
// Each type that wants to implement this interface must support concurrent calls
// to the interface methods.
// Besides, the number of concurrent calls may be very high, so long critical sections
// should be avoided (i.e.: avoid using a single lock for slow logging operations).
type LogRecordNotifier interface {
	// NewProxyLogRecord is called for each new log record
	NewProxyLogRecord(l *LogRecord) error
}

func NewProcyAccessLogger(logger *slog.Logger, config ProxyAccessLoggerConfig, notifier LogRecordNotifier) ProxyAccessLogger {
	return &proxyAccessLogger{
		logger:   logger,
		notifier: notifier,
		metadata: option.Config.AgentLabels, // TODO: use value from config struct
	}
}

func (r *proxyAccessLogger) Log(lr *LogRecord) {
	flowdebug.Log(func() (*logrus.Entry, string) {
		return lr.getLogFields(), "Logging flow record"
	})

	lr.Metadata = r.metadata

	r.notifier.NewProxyLogRecord(lr)
}
