// Copyright 2019 Authors of Hubble
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

package seven

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/gogo/protobuf/types"
	"github.com/google/gopacket/layers"
	lru "github.com/hashicorp/golang-lru"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/parser/errors"
	"github.com/cilium/hubble/pkg/parser/getters"
	"github.com/cilium/hubble/pkg/parser/options"
)

// Parser is a parser for L7 payloads
type Parser struct {
	cache         *lru.Cache
	dnsGetter     getters.DNSGetter
	ipGetter      getters.IPGetter
	serviceGetter getters.ServiceGetter
}

// New returns a new L7 parser
func New(dnsGetter getters.DNSGetter, ipGetter getters.IPGetter, serviceGetter getters.ServiceGetter, opts ...options.Option) (*Parser, error) {
	args := &options.Options{
		CacheSize: 10000,
	}

	for _, opt := range opts {
		opt(args)
	}

	cache, err := lru.New(args.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %v", err)
	}

	return &Parser{
		cache:         cache,
		dnsGetter:     dnsGetter,
		ipGetter:      ipGetter,
		serviceGetter: serviceGetter,
	}, nil
}

// Decode decodes the data from 'payload' into 'decoded'
func (p *Parser) Decode(payload *pb.Payload, decoded *pb.Flow) error {
	if payload == nil || len(payload.Data) == 0 {
		return errors.ErrEmptyData
	}

	eventType := payload.Data[0]
	if eventType != monitorAPI.MessageTypeAccessLog {
		return errors.NewErrInvalidType(eventType)
	}

	buf := bytes.NewBuffer(payload.Data[1:])
	dec := gob.NewDecoder(buf)
	r := &accesslog.LogRecord{}
	if err := dec.Decode(r); err != nil {
		return fmt.Errorf("unable to decode l7 log record: %s", err)
	}

	timestamp, pbTimestamp, err := decodeTime(r.Timestamp)
	if err != nil {
		return err
	}

	// Workaround for Cilium behavior until
	// https://github.com/cilium/cilium/issues/9558 is fixed: L7 records
	// use the same addressing tuple for both request and response.  Switch
	// the source and destination endpoint info based on the
	// request/response direction to allow aggregation to work and to
	// provide a consistent experience with L3/L4 flows.
	var sourceEndpoint, destinationEndpoint accesslog.EndpointInfo
	if r.Type == accesslog.TypeResponse {
		sourceEndpoint = r.DestinationEndpoint
		destinationEndpoint = r.SourceEndpoint
	} else {
		sourceEndpoint = r.SourceEndpoint
		destinationEndpoint = r.DestinationEndpoint
	}

	ip := decodeIP(r.IPVersion, sourceEndpoint, destinationEndpoint)

	sourceIP := net.ParseIP(ip.Source)
	destinationIP := net.ParseIP(ip.Destination)
	var sourceNames, destinationNames []string
	var sourceNamespace, sourcePod, destinationNamespace, destinationPod string
	if p.dnsGetter != nil {
		sourceNames = p.dnsGetter.GetNamesOf(sourceEndpoint.ID, sourceIP)
		destinationNames = p.dnsGetter.GetNamesOf(destinationEndpoint.ID, destinationIP)
	}
	if p.ipGetter != nil {
		if id, ok := p.ipGetter.GetIPIdentity(sourceIP); ok {
			sourceNamespace, sourcePod = id.Namespace, id.PodName
		}
		if id, ok := p.ipGetter.GetIPIdentity(destinationIP); ok {
			destinationNamespace, destinationPod = id.Namespace, id.PodName
		}
	}

	l4, sourcePort, destinationPort := decodeLayer4(r.TransportProtocol, sourceEndpoint, destinationEndpoint)
	var sourceService, destinationService *pb.Service
	if p.serviceGetter != nil {
		if srcService, ok := p.serviceGetter.GetServiceByAddr(sourceIP, sourcePort); ok {
			sourceService = &srcService
		}
		if dstService, ok := p.serviceGetter.GetServiceByAddr(destinationIP, destinationPort); ok {
			destinationService = &dstService
		}
	}

	decoded.Time = pbTimestamp
	decoded.Verdict = decodeVerdict(r.Verdict)
	decoded.DropReason = 0
	decoded.IP = ip
	decoded.L4 = l4
	decoded.Source = decodeEndpoint(sourceEndpoint, sourceNamespace, sourcePod)
	decoded.Destination = decodeEndpoint(destinationEndpoint, destinationNamespace, destinationPod)
	decoded.Type = pb.FlowType_L7
	decoded.NodeName = payload.HostName
	decoded.SourceNames = sourceNames
	decoded.DestinationNames = destinationNames
	decoded.L7 = decodeLayer7(r)
	decoded.L7.LatencyNs = p.computeResponseTime(r, timestamp)
	decoded.Reply = decodeIsReply(r.Type)
	decoded.EventType = decodeCiliumEventType(eventType)
	decoded.SourceService = sourceService
	decoded.DestinationService = destinationService
	decoded.Summary = p.getSummary(r, decoded)

	return nil
}

func (p *Parser) computeResponseTime(r *accesslog.LogRecord, timestamp time.Time) uint64 {
	var requestID string
	if r.HTTP != nil {
		requestID = r.HTTP.Headers.Get("X-Request-Id")
	}

	if requestID == "" {
		return 0
	}

	switch r.Type {
	case accesslog.TypeRequest:
		p.cache.Add(requestID, timestamp)
	case accesslog.TypeResponse:
		value, ok := p.cache.Get(requestID)
		if !ok {
			return 0
		}
		p.cache.Remove(requestID)
		requestTimestamp, ok := value.(time.Time)
		if !ok {
			return 0
		}
		latency := timestamp.Sub(requestTimestamp).Nanoseconds()
		if latency < 0 {
			return 0
		}
		return uint64(latency)
	}

	return 0
}

func decodeTime(timestamp string) (goTime time.Time, pbTime *types.Timestamp, err error) {
	goTime, err = time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return
	}

	pbTime, err = types.TimestampProto(goTime)
	if err != nil {
		return
	}

	return goTime, pbTime, err
}

func decodeVerdict(verdict accesslog.FlowVerdict) pb.Verdict {
	switch verdict {
	case accesslog.VerdictDenied:
		return pb.Verdict_DROPPED
	case accesslog.VerdictForwarded:
		return pb.Verdict_FORWARDED
	default:
		return pb.Verdict_VERDICT_UNKNOWN
	}
}

func decodeIP(version accesslog.IPVersion, source, destination accesslog.EndpointInfo) *pb.IP {
	switch version {
	case accesslog.VersionIPv4:
		return &pb.IP{
			Source:      source.IPv4,
			Destination: destination.IPv4,
			IpVersion:   pb.IPVersion_IPv4,
		}
	case accesslog.VersionIPV6:
		return &pb.IP{
			Source:      source.IPv6,
			Destination: destination.IPv6,
			IpVersion:   pb.IPVersion_IPv6,
		}
	default:
		return nil
	}
}

func decodeLayer4(protocol accesslog.TransportProtocol, source, destination accesslog.EndpointInfo) (l4 *pb.Layer4, srcPort, dstPort uint16) {
	switch u8proto.U8proto(protocol) {
	case u8proto.TCP:
		return &pb.Layer4{
			Protocol: &pb.Layer4_TCP{
				TCP: &pb.TCP{
					SourcePort:      uint32(source.Port),
					DestinationPort: uint32(destination.Port),
				},
			},
		}, uint16(source.Port), uint16(destination.Port)
	case u8proto.UDP:
		return &pb.Layer4{
			Protocol: &pb.Layer4_UDP{
				UDP: &pb.UDP{
					SourcePort:      uint32(source.Port),
					DestinationPort: uint32(destination.Port),
				},
			},
		}, uint16(source.Port), uint16(destination.Port)
	default:
		return nil, 0, 0
	}
}

func decodeEndpoint(endpoint accesslog.EndpointInfo, namespace, podName string) *pb.Endpoint {
	labels := endpoint.Labels
	sort.Strings(labels)
	return &pb.Endpoint{
		ID:        endpoint.ID,
		Identity:  endpoint.Identity,
		Namespace: namespace,
		Labels:    labels,
		PodName:   podName,
	}
}

func decodeDNS(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) *pb.Layer7_Dns {
	qtypes := make([]string, 0, len(dns.QTypes))
	for _, qtype := range dns.QTypes {
		qtypes = append(qtypes, layers.DNSType(qtype).String())
	}
	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &pb.Layer7_Dns{
			Dns: &pb.DNS{
				Query:             dns.Query,
				ObservationSource: string(dns.ObservationSource),
				Qtypes:            qtypes,
			},
		}
	}
	ips := make([]string, 0, len(dns.IPs))
	for _, ip := range dns.IPs {
		ips = append(ips, ip.String())
	}
	rtypes := make([]string, 0, len(dns.AnswerTypes))
	for _, rtype := range dns.AnswerTypes {
		rtypes = append(rtypes, layers.DNSType(rtype).String())
	}
	return &pb.Layer7_Dns{
		Dns: &pb.DNS{
			Query:             dns.Query,
			Ips:               ips,
			Ttl:               dns.TTL,
			Cnames:            dns.CNAMEs,
			ObservationSource: string(dns.ObservationSource),
			Rcode:             uint32(dns.RCode),
			Qtypes:            qtypes,
			Rrtypes:           rtypes,
		},
	}
}

func decodeHTTP(flowType accesslog.FlowType, http *accesslog.LogRecordHTTP) *pb.Layer7_Http {
	var headers []*pb.HTTPHeader
	var keys []string
	for key := range http.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range http.Headers[key] {
			headers = append(headers, &pb.HTTPHeader{Key: key, Value: value})
		}
	}
	var urlString string
	if http.URL != nil {
		if http.URL.User != nil {
			// Don't include the password in the flow.
			if _, ok := http.URL.User.Password(); ok {
				http.URL.User = url.UserPassword(http.URL.User.Username(), "HUBBLE_REDACTED")
			}
		}
		urlString = http.URL.String()
	}
	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &pb.Layer7_Http{
			Http: &pb.HTTP{
				Method:   http.Method,
				Protocol: http.Protocol,
				Url:      urlString,
				Headers:  headers,
			},
		}
	}

	return &pb.Layer7_Http{
		Http: &pb.HTTP{
			Code:     uint32(http.Code),
			Method:   http.Method,
			Protocol: http.Protocol,
			Url:      urlString,
			Headers:  headers,
		},
	}
}

func decodeLayer7(r *accesslog.LogRecord) *pb.Layer7 {
	var flowType pb.L7FlowType
	switch r.Type {
	case accesslog.TypeRequest:
		flowType = pb.L7FlowType_REQUEST
	case accesslog.TypeResponse:
		flowType = pb.L7FlowType_RESPONSE
	case accesslog.TypeSample:
		flowType = pb.L7FlowType_SAMPLE
	}

	switch {
	case r.DNS != nil:
		return &pb.Layer7{
			Type:   flowType,
			Record: decodeDNS(r.Type, r.DNS),
		}
	case r.HTTP != nil:
		return &pb.Layer7{
			Type:   flowType,
			Record: decodeHTTP(r.Type, r.HTTP),
		}
	case r.Kafka != nil:
		return &pb.Layer7{
			Type:   flowType,
			Record: decodeKafka(r.Type, r.Kafka),
		}
	default:
		return &pb.Layer7{
			Type: flowType,
		}
	}
}

func decodeIsReply(t accesslog.FlowType) bool {
	return t == accesslog.TypeResponse
}

func decodeCiliumEventType(eventType uint8) *pb.CiliumEventType {
	return &pb.CiliumEventType{
		Type: int32(eventType),
	}
}

func (p *Parser) httpSummary(flowType accesslog.FlowType, http *accesslog.LogRecordHTTP, flow *pb.Flow) string {
	httpRequest := fmt.Sprintf("%s %s", http.Method, http.URL)
	switch flowType {
	case accesslog.TypeRequest:
		return fmt.Sprintf("%s %s", http.Protocol, httpRequest)
	case accesslog.TypeResponse:
		return fmt.Sprintf("%s %d %dms (%s)", http.Protocol, http.Code, uint64(time.Duration(flow.GetL7().LatencyNs)/time.Millisecond), httpRequest)
	}
	return ""
}

func kafkaSummary(flow *pb.Flow) string {
	kafka := flow.GetL7().GetKafka()
	if kafka == nil {
		return ""
	}
	if flow.GetL7().Type == pb.L7FlowType_REQUEST {
		return fmt.Sprintf("Kafka request %s correlation id %d topic '%s'",
			kafka.ApiKey,
			kafka.CorrelationId,
			kafka.Topic)
	}
	// response
	return fmt.Sprintf("Kafka response %s correlation id %d topic '%s' return code %d",
		kafka.ApiKey,
		kafka.CorrelationId,
		kafka.Topic,
		kafka.ErrorCode)
}

func dnsSummary(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) string {
	types := []string{}
	for _, t := range dns.QTypes {
		types = append(types, layers.DNSType(t).String())
	}
	qTypeStr := strings.Join(types, ",")

	switch flowType {
	case accesslog.TypeRequest:
		return fmt.Sprintf("DNS Query %s %s", dns.Query, qTypeStr)
	case accesslog.TypeResponse:
		rcode := layers.DNSResponseCode(dns.RCode)

		var answer string
		if rcode != layers.DNSResponseCodeNoErr {
			answer = fmt.Sprintf("RCode: %s", rcode)
		} else {
			parts := make([]string, 0)

			if len(dns.IPs) > 0 {
				ips := make([]string, 0, len(dns.IPs))
				for _, ip := range dns.IPs {
					ips = append(ips, ip.String())
				}
				parts = append(parts, fmt.Sprintf("%q", strings.Join(ips, ",")))
			}

			if len(dns.CNAMEs) > 0 {
				parts = append(parts, fmt.Sprintf("CNAMEs: %q", strings.Join(dns.CNAMEs, ",")))
			}

			answer = strings.Join(parts, " ")
		}

		sourceType := "Query"
		if dns.ObservationSource == accesslog.DNSSourceAgentPoller {
			sourceType = "Poll"
		}

		return fmt.Sprintf("DNS Answer %s TTL: %d (%s %s %s)", answer, dns.TTL, sourceType, dns.Query, qTypeStr)
	}

	return ""
}

func genericSummary(l7 *accesslog.LogRecordL7) string {
	return fmt.Sprintf("%s Fields: %s", l7.Proto, l7.Fields)
}

func (p *Parser) getSummary(logRecord *accesslog.LogRecord, flow *pb.Flow) string {
	if logRecord == nil {
		return ""
	}
	if http := logRecord.HTTP; http != nil {
		return p.httpSummary(logRecord.Type, http, flow)
	} else if kafka := logRecord.Kafka; kafka != nil {
		return kafkaSummary(flow)
	} else if dns := logRecord.DNS; dns != nil {
		return dnsSummary(logRecord.Type, dns)
	} else if generic := logRecord.L7; generic != nil {
		return genericSummary(generic)
	}

	return ""
}

func decodeKafka(flowType accesslog.FlowType, kafka *accesslog.LogRecordKafka) *pb.Layer7_Kafka {
	if flowType == accesslog.TypeRequest {
		return &pb.Layer7_Kafka{
			Kafka: &pb.Kafka{
				ApiVersion:    int32(kafka.APIVersion),
				ApiKey:        kafka.APIKey,
				CorrelationId: kafka.CorrelationID,
				Topic:         kafka.Topic.Topic,
			},
		}
	}
	return &pb.Layer7_Kafka{
		Kafka: &pb.Kafka{
			ErrorCode:     int32(kafka.ErrorCode),
			ApiVersion:    int32(kafka.APIVersion),
			ApiKey:        kafka.APIKey,
			CorrelationId: kafka.CorrelationID,
			Topic:         kafka.Topic.Topic,
		},
	}
}
