// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	log = logging.DefaultLogger

	logMutex lock.Mutex
	logger   *lumberjack.Logger
	notifier LogRecordNotifier
	logPath  string
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

// LogRecordProducer defines the interface that a proxy has to implement in
// order to support access logging
type LogRecordProducer interface {
	// DeriveEndpointInfo must lookup the endpoint by IP and fill the
	// endpoint's parameters into the EndpointInfo struct. The function
	// must return true if the endpoint was found.
	DeriveEndpointInfo(ip net.IP, info *accesslog.EndpointInfo) bool

	// LocalEndpoint must return information about the local endpoint which
	// either sent the request (for egress) or is receiving the request
	// (for ingress)
	LocalEndpointInfo() accesslog.EndpointInfo

	// GetObservationPoint must return the ObservationPoint at which the log record is being produced
	GetObservationPoint() accesslog.ObservationPoint

	// UpdateAccounting is called for each log record as soon as the log
	// verdict is known
	UpdateAccounting(t accesslog.FlowType, v accesslog.FlowVerdict)
}

// fillIdentity resolves the labels of the specified identity if known
// locally and fills in the following info member fields:
//  - info.Identity
//  - info.Labels
//  - info.LabelsSHA256
func fillIdentity(info *accesslog.EndpointInfo, id identity.NumericIdentity) {
	info.Identity = uint64(id)

	if identity := identity.LookupIdentityByID(id); identity != nil {
		info.Labels = identity.Labels.GetModel()
		info.LabelsSHA256 = identity.GetLabelsSHA256()
	}
}

// fillEndpointInfo tries to resolve the IP address and fills the EndpointInfo
// fields with either ReservedIdentityHost or ReservedIdentityWorld
func fillEndpointInfo(producer LogRecordProducer, info *accesslog.EndpointInfo, ip net.IP) {
	if ip.To4() != nil {
		info.IPv4 = ip.String()

		// first we try to resolve and check if the IP is
		// same as Host
		if node.IsHostIPv4(ip) {
			fillIdentity(info, identity.ReservedIdentityHost)
			return
		}

		// If Host IP check fails, we try to resolve and check
		// if IP belongs to the cluster.
		if node.GetIPv4ClusterRange().Contains(ip) {
			// If endpoint cannot be found, set to cluster identity
			if !producer.DeriveEndpointInfo(ip, info) {
				fillIdentity(info, identity.ReservedIdentityCluster)
			}
		} else {
			// If we are unable to resolve the HostIP as well
			// as the cluster IP we mark this as a 'world' identity.
			fillIdentity(info, identity.ReservedIdentityWorld)
		}
	} else {
		info.IPv6 = ip.String()

		if node.IsHostIPv6(ip) {
			fillIdentity(info, identity.ReservedIdentityHost)
			return
		}

		if node.GetIPv6ClusterRange().Contains(ip) {
			if !producer.DeriveEndpointInfo(ip, info) {
				fillIdentity(info, identity.ReservedIdentityCluster)
			}
		} else {
			fillIdentity(info, identity.ReservedIdentityWorld)
		}
	}
}

// fillIngressSourceInfo fills the EndpointInfo fields, by fetching
// the consumable from the consumable cache of endpoint using identity sent by
// source. This is needed in ingress proxy while logging the source endpoint
// info.  Since there will be 2 proxies on the same host, if both egress and
// ingress policies are set, the ingress policy cannot determine the source
// endpoint info based on ip address, as the ip address would be that of the
// egress proxy i.e host.
func fillIngressSourceInfo(producer LogRecordProducer, info *accesslog.EndpointInfo, ip *net.IP, srcIdentity uint32) {
	if srcIdentity != 0 {
		if ip != nil {
			if ip.To4() != nil {
				info.IPv4 = ip.String()
			} else {
				info.IPv6 = ip.String()
			}
		}
		fillIdentity(info, identity.NumericIdentity(srcIdentity))
	} else {
		// source security identity 0 is possible when somebody else other than
		// the BPF datapath attempts to
		// connect to the proxy.
		// We should try to resolve if the identity belongs to reserved_host
		// or reserved_world.
		if ip != nil {
			fillEndpointInfo(producer, info, *ip)
		} else {
			log.Warn("Missing security identity in source endpoint info")
		}
	}
}

// fillEgressDestinationInfo returns the destination EndpointInfo for a flow
// leaving the proxy at egress.
func fillEgressDestinationInfo(producer LogRecordProducer, info *accesslog.EndpointInfo, ipstr string) {
	ip := net.ParseIP(ipstr)
	if ip != nil {
		fillEndpointInfo(producer, info, ip)
	}
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

		lr.producer.UpdateAccounting(lr.Type, lr.Verdict)
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
	SrcIdentity uint32
}

// Addressing attaches addressing information about the source and destination
// to the logrecord
func (logTags) Addressing(i AddressingInfo) LogTag {
	return func(lr *LogRecord) {
		switch lr.ObservationPoint {
		case accesslog.Ingress:
			lr.DestinationEndpoint = lr.producer.LocalEndpointInfo()
		case accesslog.Egress:
			lr.SourceEndpoint = lr.producer.LocalEndpointInfo()
		}

		ipstr, port, err := net.SplitHostPort(i.SrcIPPort)
		if err == nil {
			ip := net.ParseIP(ipstr)
			if ip != nil && ip.To4() == nil {
				lr.IPVersion = accesslog.VersionIPV6
			}

			p, err := strconv.ParseUint(port, 10, 16)
			if err == nil {
				lr.SourceEndpoint.Port = uint16(p)
				if lr.ObservationPoint == accesslog.Ingress {
					fillIngressSourceInfo(lr.producer, &lr.SourceEndpoint, &ip, i.SrcIdentity)
				}
			}
		}

		ipstr, port, err = net.SplitHostPort(i.DstIPPort)
		if err == nil {
			p, err := strconv.ParseUint(port, 10, 16)
			if err == nil {
				lr.DestinationEndpoint.Port = uint16(p)
				if lr.ObservationPoint == accesslog.Egress {
					fillEgressDestinationInfo(lr.producer, &lr.DestinationEndpoint, ipstr)
				}
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

// LogRecord is a proxy log record based off accesslog.LogRecord
type LogRecord struct {
	accesslog.LogRecord

	// producer is a reference to whoever produced this log record
	producer LogRecordProducer
}

// NewLogRecord creates a new log record and applies optional tags
//
// Example:
// record := logger.NewLogRecord(flowType, observationPoint,
//                logger.LogTags.Timestamp(time.Now()))
func NewLogRecord(producer LogRecordProducer, t accesslog.FlowType, tags ...LogTag) LogRecord {
	lr := LogRecord{
		LogRecord: accesslog.LogRecord{
			Type:              t,
			ObservationPoint:  producer.GetObservationPoint(),
			IPVersion:         accesslog.VersionIPv4,
			TransportProtocol: 6,
			Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
			NodeAddressInfo: accesslog.NodeAddressInfo{
				IPv4: node.GetExternalIPv4().String(),
				IPv6: node.GetIPv6().String(),
			},
		},
		producer: producer,
	}

	for _, tagFn := range tags {
		tagFn(&lr)
	}

	return lr
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

func (lr *LogRecord) getRawLogMessage() []byte {
	b, err := json.Marshal(*lr)
	if err != nil {
		return []byte(err.Error())
	}

	return append(b, byte('\n'))
}

// Log logs a record to the logfile and flushes the buffer
func (lr *LogRecord) Log() {
	flowdebug.Log(lr.getLogFields(), "Logging flow record")

	// Lock while writing access log so we serialize writes as we may have
	// to reopen the logfile and parallel writes could fail because of that
	logMutex.Lock()
	defer logMutex.Unlock()

	lr.Metadata = metadata

	if notifier != nil {
		notifier.NewProxyLogRecord(lr)
	}

	if logger == nil {
		flowdebug.Log(log.WithField(FieldFilePath, logPath),
			"Skipping writing to access log (logger nil)")
		return
	}

	if _, err := logger.Write(lr.getRawLogMessage()); err != nil {
		log.WithError(err).WithField(FieldFilePath, logPath).
			Errorf("Error writing to access file")
	}
}

// Called with lock held
func openLogfileLocked(lf string) error {
	logPath = lf
	log.WithField(FieldFilePath, logPath).Debug("Opened access log")

	logger = &lumberjack.Logger{
		Filename:   lf,
		MaxSize:    100, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	}

	return nil
}

// LogRecordNotifier is the interface to implement LogRecord notifications
type LogRecordNotifier interface {
	// NewProxyLogRecord is called for each new log record
	NewProxyLogRecord(l *LogRecord) error
}

// OpenLogfile opens a file for logging
func OpenLogfile(lf string) error {
	logMutex.Lock()
	defer logMutex.Unlock()

	return openLogfileLocked(lf)
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
