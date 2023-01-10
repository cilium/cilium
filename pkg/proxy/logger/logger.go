// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
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
	SrcIPPort   string
	DstIPPort   string
	SrcIdentity identity.NumericIdentity
	DstIdentity identity.NumericIdentity
}

// Addressing attaches addressing information about the source and destination
// to the logrecord
func (logTags) Addressing(i AddressingInfo) LogTag {
	return func(lr *LogRecord) {
		ipstr, port, err := net.SplitHostPort(i.SrcIPPort)
		if err == nil {
			ip := net.ParseIP(ipstr)
			if ip != nil && ip.To4() == nil {
				lr.IPVersion = accesslog.VersionIPV6
			}

			p, err := strconv.ParseUint(port, 10, 16)
			if err == nil {
				lr.SourceEndpoint.Port = uint16(p)
				endpointInfoRegistry.FillEndpointInfo(&lr.SourceEndpoint, ip, i.SrcIdentity)
			}
		}

		ipstr, port, err = net.SplitHostPort(i.DstIPPort)
		if err == nil {
			ip := net.ParseIP(ipstr)
			p, err := strconv.ParseUint(port, 10, 16)
			if err == nil {
				lr.DestinationEndpoint.Port = uint16(p)
				endpointInfoRegistry.FillEndpointInfo(&lr.DestinationEndpoint, ip, i.DstIdentity)
			}
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
	fields := log.WithFields(logrus.Fields{
		FieldType:    lr.Type,
		FieldVerdict: lr.Verdict,
		FieldMessage: lr.Info,
	})

	if lr.HTTP != nil {
		fields = fields.WithFields(logrus.Fields{
			FieldCode:     lr.HTTP.Code,
			FieldMethod:   lr.HTTP.Method,
			FieldURL:      lr.HTTP.URL,
			FieldProtocol: lr.HTTP.Protocol,
			FieldHeader:   lr.HTTP.Headers,
		})
	}

	if lr.Kafka != nil {
		fields = fields.WithFields(logrus.Fields{
			FieldCode:               lr.Kafka.ErrorCode,
			FieldKafkaAPIKey:        lr.Kafka.APIKey,
			FieldKafkaAPIVersion:    lr.Kafka.APIVersion,
			FieldKafkaCorrelationID: lr.Kafka.CorrelationID,
		})
	}

	return fields
}

// Log logs a record to the logfile and flushes the buffer
func (lr *LogRecord) Log() {
	flowdebug.Log(lr.getLogFields(), "Logging flow record")

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
