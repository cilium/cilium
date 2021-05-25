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

	// endpointInfoRegistry provides access to any endpoint's information given
	// its IP address.
	endpointInfoRegistry EndpointInfoRegistry

	// localEndpointInfo is the information on the local endpoint which
	// either sent the request (for egress) or is receiving the request
	// (for ingress)
	localEndpointInfo *accesslog.EndpointInfo
}

// NewLogRecord creates a new log record and applies optional tags
//
// Example:
// record := logger.NewLogRecord(localEndpointInfoSource, flowType,
//                observationPoint, logger.LogTags.Timestamp(time.Now()))
func NewLogRecord(endpointInfoRegistry EndpointInfoRegistry, localEndpointInfoSource EndpointInfoSource, t accesslog.FlowType, ingress bool, tags ...LogTag) *LogRecord {
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
		endpointInfoRegistry: endpointInfoRegistry,
		localEndpointInfo:    getEndpointInfo(localEndpointInfoSource),
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

// fillEndpointInfo tries to resolve the IP address and fills the EndpointInfo
// fields with either ReservedIdentityHost or ReservedIdentityWorld
func (lr *LogRecord) fillEndpointInfo(info *accesslog.EndpointInfo, ip net.IP) {
	if ip.To4() != nil {
		info.IPv4 = ip.String()

		// first we try to resolve and check if the IP is
		// same as Host
		if node.IsHostIPv4(ip) {
			lr.endpointInfoRegistry.FillEndpointIdentityByID(identity.ReservedIdentityHost, info)
		} else if !lr.endpointInfoRegistry.FillEndpointIdentityByIP(ip, info) {
			// If we are unable to resolve the HostIP as well
			// as the cluster IP we mark this as a 'world' identity.
			lr.endpointInfoRegistry.FillEndpointIdentityByID(identity.ReservedIdentityWorld, info)
		}
	} else {
		info.IPv6 = ip.String()

		if node.IsHostIPv6(ip) {
			lr.endpointInfoRegistry.FillEndpointIdentityByID(identity.ReservedIdentityHost, info)
		} else if !lr.endpointInfoRegistry.FillEndpointIdentityByIP(ip, info) {
			lr.endpointInfoRegistry.FillEndpointIdentityByID(identity.ReservedIdentityWorld, info)
		}
	}
}

// fillIngressSourceInfo fills the EndpointInfo fields using identity sent by
// source. This is needed in ingress proxy while logging the source endpoint
// info.  Since there will be 2 proxies on the same host, if both egress and
// ingress policies are set, the ingress policy cannot determine the source
// endpoint info based on ip address, as the ip address would be that of the
// egress proxy i.e host.
func (lr *LogRecord) fillIngressSourceInfo(info *accesslog.EndpointInfo, ip *net.IP, srcIdentity uint32) {
	if srcIdentity != 0 {
		if ip != nil {
			if ip.To4() != nil {
				info.IPv4 = ip.String()
			} else {
				info.IPv6 = ip.String()
			}
		}
		lr.endpointInfoRegistry.FillEndpointIdentityByID(identity.NumericIdentity(srcIdentity), info)
	} else {
		// source security identity 0 is possible when somebody else other than
		// the BPF datapath attempts to
		// connect to the proxy.
		// We should try to resolve if the identity belongs to reserved_host
		// or reserved_world.
		if ip != nil {
			lr.fillEndpointInfo(info, *ip)
		} else {
			log.Warn("Missing security identity in source endpoint info")
		}
	}
}

// fillEgressDestinationInfo returns the destination EndpointInfo for a flow
// leaving the proxy at egress.
func (lr *LogRecord) fillEgressDestinationInfo(info *accesslog.EndpointInfo, ipstr string) {
	ip := net.ParseIP(ipstr)
	if ip != nil {
		lr.fillEndpointInfo(info, ip)
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
			lr.DestinationEndpoint = *lr.localEndpointInfo
		case accesslog.Egress:
			lr.SourceEndpoint = *lr.localEndpointInfo
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
					lr.fillIngressSourceInfo(&lr.SourceEndpoint, &ip, i.SrcIdentity)
				}
			}
		}

		ipstr, port, err = net.SplitHostPort(i.DstIPPort)
		if err == nil {
			p, err := strconv.ParseUint(port, 10, 16)
			if err == nil {
				lr.DestinationEndpoint.Port = uint16(p)
				if lr.ObservationPoint == accesslog.Egress {
					lr.fillEgressDestinationInfo(&lr.DestinationEndpoint, ipstr)
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
	defer logMutex.Unlock()

	lr.Metadata = metadata

	if notifier != nil {
		notifier.NewProxyLogRecord(lr)
	}
}

// LogRecordNotifier is the interface to implement LogRecord notifications
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
