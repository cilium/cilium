// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/option"
)

type ProxyAccessLogger interface{}

type proxyAccessLogger struct {
	logger *slog.Logger

	notifier LogRecordNotifier
	metadata []string
}

func newProcyAccessLogger(logger *slog.Logger, config proxyAccessLoggerConfig, notifier LogRecordNotifier) ProxyAccessLogger {
	return &proxyAccessLogger{
		logger:   logger,
		notifier: notifier,
		metadata: option.Config.AgentLabels, // TODO: use value from config struct
	}
}
