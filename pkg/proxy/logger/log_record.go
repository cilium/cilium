// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
)

// fields used for structured logging
const (
	FieldType     = "type"
	FieldVerdict  = "verdict"
	FieldCode     = "code"
	FieldMethod   = "method"
	FieldURL      = "url"
	FieldProtocol = "protocol"
	FieldHeader   = "header"
	FieldFilePath = logfields.Path
	FieldMessage  = "message"
)

// fields used for structured logging of Kafka messages
const (
	FieldKafkaAPIKey        = "kafkaApiKey"
	FieldKafkaAPIVersion    = "kafkaApiVersion"
	FieldKafkaCorrelationID = "kafkaCorrelationID"
)

// LogRecord is a proxy log record based off accesslog.LogRecord.
type LogRecord struct {
	accesslog.LogRecord
}

// LogTag attaches a tag to a log record
type LogTag func(lr *LogRecord, endpointInfoRegistry EndpointInfoRegistry)

// LogTags are optional structured tags that can be attached to log records.
// See NewLogRecord() and ApplyTags() for example usage.
var LogTags logTags

type logTags struct{}

// Verdict attach verdict information to the log record
func (logTags) Verdict(v accesslog.FlowVerdict, info string) LogTag {
	return func(lr *LogRecord, _ EndpointInfoRegistry) {
		lr.Verdict = v
		lr.Info = info
	}
}

// Timestamp overwrites the starting timestamp of the log record
func (logTags) Timestamp(ts time.Time) LogTag {
	return func(lr *LogRecord, _ EndpointInfoRegistry) {
		lr.Timestamp = ts.UTC().Format(time.RFC3339Nano)
	}
}

// AddressingInfo is the information passed in via the Addressing() tag
type AddressingInfo struct {
	SrcIPPort string
	DstIPPort string

	SrcIdentity    identity.NumericIdentity
	SrcSecIdentity *identity.Identity
	SrcEPID        uint64

	DstIdentity    identity.NumericIdentity
	DstSecIdentity *identity.Identity
	DstEPID        uint64
}

// Addressing attaches addressing information about the source and destination
// to the logrecord
func (logTags) Addressing(ctx context.Context, i AddressingInfo) LogTag {
	return func(lr *LogRecord, endpointInfoRegistry EndpointInfoRegistry) {
		lr.SourceEndpoint.ID = i.SrcEPID
		if i.SrcSecIdentity != nil {
			lr.SourceEndpoint.Identity = uint64(i.SrcSecIdentity.ID)
			lr.SourceEndpoint.Labels = i.SrcSecIdentity.LabelArray
		} else {
			lr.SourceEndpoint.Identity = uint64(i.SrcIdentity)
		}

		addrPort, err := netip.ParseAddrPort(i.SrcIPPort)
		if err == nil {
			if addrPort.Addr().Is6() {
				lr.IPVersion = accesslog.VersionIPV6
			}

			lr.SourceEndpoint.Port = addrPort.Port()
			endpointInfoRegistry.FillEndpointInfo(ctx, &lr.SourceEndpoint, addrPort.Addr())
		}

		lr.DestinationEndpoint.ID = i.DstEPID
		if i.DstSecIdentity != nil {
			lr.DestinationEndpoint.Identity = uint64(i.DstSecIdentity.ID)
			lr.DestinationEndpoint.Labels = i.DstSecIdentity.LabelArray
		} else {
			lr.DestinationEndpoint.Identity = uint64(i.DstIdentity)
		}

		addrPort, err = netip.ParseAddrPort(i.DstIPPort)
		if err == nil {
			lr.DestinationEndpoint.Port = addrPort.Port()
			endpointInfoRegistry.FillEndpointInfo(ctx, &lr.DestinationEndpoint, addrPort.Addr())
		}
	}
}

// HTTP attaches HTTP information to the log record
func (logTags) HTTP(h *accesslog.LogRecordHTTP) LogTag {
	return func(lr *LogRecord, _ EndpointInfoRegistry) {
		lr.HTTP = h
	}
}

// Kafka attaches Kafka information to the log record
func (logTags) Kafka(k *accesslog.LogRecordKafka) LogTag {
	return func(lr *LogRecord, _ EndpointInfoRegistry) {
		lr.Kafka = k
	}
}

// DNS attaches DNS information to the log record
func (logTags) DNS(d *accesslog.LogRecordDNS) LogTag {
	return func(lr *LogRecord, _ EndpointInfoRegistry) {
		lr.DNS = d
	}
}

// L7 attaches generic L7 information to the log record
func (logTags) L7(h *accesslog.LogRecordL7) LogTag {
	return func(lr *LogRecord, _ EndpointInfoRegistry) {
		lr.L7 = h
	}
}

func (lr *LogRecord) getLogFields() []any {
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

// EndpointInfoRegistry provides endpoint information lookup by endpoint IP address.
type EndpointInfoRegistry interface {
	// FillEndpointInfo resolves the labels of the specified identity if known locally.
	// ID and Labels should be provided in 'info' if known.
	// If 'id' is passed as zero, will locate the EP by 'addr', and also fill info.ID, if found.
	// Fills in the following info member fields:
	//  - info.IPv4           (if 'ip' is IPv4)
	//  - info.IPv6           (if 'ip' is not IPv4)
	//  - info.Identity       (defaults to WORLD if not known)
	//  - info.Labels         (only if identity is found)
	FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr)
}
