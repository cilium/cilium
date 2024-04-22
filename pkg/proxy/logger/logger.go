// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"context"
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "proxy-logger")

	logMutex lock.Mutex
	notifier LogRecordNotifier
	metadata []string
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

// endpointInfoRegistry provides access to any endpoint's information given
// its IP address.
var endpointInfoRegistry EndpointInfoRegistry

func SetEndpointInfoRegistry(epInfoRegistry EndpointInfoRegistry) {
	endpointInfoRegistry = epInfoRegistry
}

// NewLogRecord creates a new log record and applies optional tags
//
// Example:
// record := logger.NewLogRecord(flowType, observationPoint, logger.LogTags.Timestamp(time.Now()))
func NewLogRecord(t accesslog.FlowType, ingress bool, tags ...LogTag) *LogRecord {
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
		tagFn(&lr)
	}

	return &lr
}

// LogTag attaches a tag to a log record
type LogTag func(lr *LogRecord)

// LogTags are optional structured tags that can be attached to log records.
// See NewLogRecord() and ApplyTags() for example usage.
var LogTags logTags

type logTags struct{}

// Verdict attachs verdict information to the log record
func (logTags) Verdict(v accesslog.FlowVerdict, info string) LogTag {
	return func(lr *LogRecord) {
		lr.Verdict = v
		lr.Info = info
	}
}

// Timestamp overwrites the starting timestamp of the log record
func (logTags) Timestamp(ts time.Time) LogTag {
	return func(lr *LogRecord) {
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
	return func(lr *LogRecord) {
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
	return func(lr *LogRecord) {
		lr.HTTP = h
	}
}

// Kafka attaches Kafka information to the log record
func (logTags) Kafka(k *accesslog.LogRecordKafka) LogTag {
	return func(lr *LogRecord) {
		lr.Kafka = k
	}
}

// DNS attaches DNS information to the log record
func (logTags) DNS(d *accesslog.LogRecordDNS) LogTag {
	return func(lr *LogRecord) {
		lr.DNS = d
	}
}

// L7 attaches generic L7 information to the log record
func (logTags) L7(h *accesslog.LogRecordL7) LogTag {
	return func(lr *LogRecord) {
		lr.L7 = h
	}
}

// ApplyTags applies tags to an existing log record
//
// Example:
// lr.ApplyTags(logger.LogTags.Verdict(verdict, info))
func (lr *LogRecord) ApplyTags(tags ...LogTag) {
	for _, tagFn := range tags {
		tagFn(lr)
	}
}

func (lr *LogRecord) getLogFields() *logrus.Entry {
	fields := make(logrus.Fields, 8) // at most 8 entries, avoid map grow

	fields[FieldType] = lr.Type
	fields[FieldVerdict] = lr.Verdict
	fields[FieldMessage] = lr.Info

	if lr.HTTP != nil {
		fields[FieldCode] = lr.HTTP.Code
		fields[FieldMethod] = lr.HTTP.Method
		fields[FieldURL] = lr.HTTP.URL
		fields[FieldProtocol] = lr.HTTP.Protocol
		fields[FieldHeader] = lr.HTTP.Headers
	}

	if lr.Kafka != nil {
		fields[FieldCode] = lr.Kafka.ErrorCode
		fields[FieldKafkaAPIKey] = lr.Kafka.APIKey
		fields[FieldKafkaAPIVersion] = lr.Kafka.APIVersion
		fields[FieldKafkaCorrelationID] = lr.Kafka.CorrelationID
	}

	return log.WithFields(fields)
}

// Log logs a record to the logfile and flushes the buffer
func (lr *LogRecord) Log() {
	flowdebug.Log(func() (*logrus.Entry, string) {
		return lr.getLogFields(), "Logging flow record"
	})

	logMutex.Lock()
	lr.Metadata = metadata
	n := notifier
	logMutex.Unlock()

	if n != nil {
		n.NewProxyLogRecord(lr)
	}
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

// SetNotifier sets the notifier to call for all L7 records
func SetNotifier(n LogRecordNotifier) {
	logMutex.Lock()
	notifier = n
	logMutex.Unlock()
}

// SetMetadata sets the metadata to include in each record
func SetMetadata(md []string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	metadata = md
}

// EndpointInfoRegistry provides endpoint information lookup by endpoint IP address.
type EndpointInfoRegistry interface {
	// FillEndpointInfo resolves the labels of the specified identity if known locally.
	// ID and Labels should be provieded in 'info' if known.
	// If 'id' is passed as zero, will locate the EP by 'addr', and also fill info.ID, if found.
	// Fills in the following info member fields:
	//  - info.IPv4           (if 'ip' is IPv4)
	//  - info.IPv6           (if 'ip' is not IPv4)
	//  - info.Identity       (defaults to WORLD if not known)
	//  - info.Labels         (only if identity is found)
	FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr)
}
