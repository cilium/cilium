// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"log/slog"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
)

type ProxyAccessLogger interface {
	// NewLogRecord creates a new log record and applies optional tags
	//
	// Example:
	// NewLogRecord(flowType, observationPoint, logger.LogTags.Timestamp(time.Now()))
	NewLogRecord(t accesslog.FlowType, ingress bool, tags ...LogTag) *LogRecord

	// Log logs the given log record to the flow log (if flow debug logging is enabled)
	// and sends it of to the monitor agent via notifier.
	Log(lr *LogRecord)
}

type proxyAccessLogger struct {
	logger *slog.Logger

	notifier             LogRecordNotifier
	endpointInfoRegistry EndpointInfoRegistry
	metadata             []string
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

func NewProcyAccessLogger(logger *slog.Logger, config ProxyAccessLoggerConfig, notifier LogRecordNotifier, endpointInfoRegistry EndpointInfoRegistry) ProxyAccessLogger {
	return &proxyAccessLogger{
		logger:               logger,
		notifier:             notifier,
		endpointInfoRegistry: endpointInfoRegistry,
		metadata:             option.Config.AgentLabels, // TODO: use value from config struct
	}
}

func (r *proxyAccessLogger) NewLogRecord(t accesslog.FlowType, ingress bool, tags ...LogTag) *LogRecord {
	var observationPoint accesslog.ObservationPoint
	if ingress {
		observationPoint = accesslog.Ingress
	} else {
		observationPoint = accesslog.Egress
	}

	lr := LogRecord{
		LogRecord: accesslog.LogRecord{
			Type:              t,
			ObservationPoint:  observationPoint,
			IPVersion:         accesslog.VersionIPv4,
			TransportProtocol: 6,
			Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
			NodeAddressInfo:   accesslog.NodeAddressInfo{},
		},
	}

	if ip := node.GetIPv4(); ip != nil {
		lr.LogRecord.NodeAddressInfo.IPv4 = ip.String()
	}

	if ip := node.GetIPv6(); ip != nil {
		lr.LogRecord.NodeAddressInfo.IPv6 = ip.String()
	}

	for _, tagFn := range tags {
		tagFn(&lr, r.endpointInfoRegistry)
	}

	return &lr
}

func (r *proxyAccessLogger) Log(lr *LogRecord) {
	flowdebug.Log(func() (*logrus.Entry, string) {
		return lr.getLogFields(), "Logging flow record"
	})

	lr.Metadata = r.metadata

	r.notifier.NewProxyLogRecord(lr)
}
