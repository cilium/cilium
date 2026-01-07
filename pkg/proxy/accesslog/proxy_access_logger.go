// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

type ProxyAccessLogger interface {
	// NewLogRecord creates a new log record and applies optional tags
	//
	// Example:
	// NewLogRecord(flowType, observationPoint, logger.LogTags.Timestamp(time.Now()))
	NewLogRecord(ctx context.Context, t FlowType, ingress bool, tags ...LogTag) (*LogRecord, error)

	// Log logs the given log record to the flow log (if flow debug logging is enabled)
	// and sends it of to the monitor agent via notifier.
	Log(lr *LogRecord)
}

type proxyAccessLogger struct {
	logger *slog.Logger

	notifier             LogRecordNotifier
	endpointInfoRegistry EndpointInfoRegistry
	localNodeStore       *node.LocalNodeStore
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

func NewProxyAccessLogger(logger *slog.Logger, config ProxyAccessLoggerConfig, notifier LogRecordNotifier, endpointInfoRegistry EndpointInfoRegistry, localNodeStore *node.LocalNodeStore) ProxyAccessLogger {
	return &proxyAccessLogger{
		logger:               logger,
		notifier:             notifier,
		endpointInfoRegistry: endpointInfoRegistry,
		localNodeStore:       localNodeStore,
		metadata:             config.AgentLabels,
	}
}

func (r *proxyAccessLogger) NewLogRecord(ctx context.Context, t FlowType, ingress bool, tags ...LogTag) (*LogRecord, error) {
	var observationPoint ObservationPoint
	if ingress {
		observationPoint = Ingress
	} else {
		observationPoint = Egress
	}

	lr := LogRecord{
		Type:              t,
		ObservationPoint:  observationPoint,
		IPVersion:         VersionIPv4,
		TransportProtocol: 6,
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		NodeAddressInfo:   NodeAddressInfo{},
	}

	ln, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get local node: %w", err)
	}

	if ip := ln.GetNodeIP(false); ip != nil {
		lr.NodeAddressInfo.IPv4 = ip.String()
	}

	if ip := ln.GetNodeIP(true); ip != nil {
		lr.NodeAddressInfo.IPv6 = ip.String()
	}

	for _, tagFn := range tags {
		tagFn(&lr, r.endpointInfoRegistry)
	}

	return &lr, nil
}

func (r *proxyAccessLogger) Log(lr *LogRecord) {
	if flowdebug.Enabled() {
		r.logger.Debug("Logging flow record", r.getLogFields(lr)...)
	}

	lr.Metadata = r.metadata

	r.notifier.NewProxyLogRecord(lr)
}

func (r *proxyAccessLogger) getLogFields(lr *LogRecord) []any {
	fields := []any{}

	fields = append(fields,
		FieldType, lr.Type,
		FieldVerdict, lr.Verdict,
		FieldMessage, lr.Info,
	)

	if lr.HTTP != nil {
		fields = append(fields,
			FieldCode, lr.HTTP.Code,
			FieldMethod, lr.HTTP.Method,
			FieldURL, lr.HTTP.URL,
			FieldProtocol, lr.HTTP.Protocol,
			FieldHeader, lr.HTTP.Headers,
		)
	}

	if lr.Kafka != nil {
		fields = append(fields,
			FieldCode, lr.Kafka.ErrorCode,
			FieldKafkaAPIVersion, lr.Kafka.APIVersion,
			FieldKafkaAPIKey, lr.Kafka.APIKey,
			FieldKafkaCorrelationID, lr.Kafka.CorrelationID,
		)
	}

	return fields
}
