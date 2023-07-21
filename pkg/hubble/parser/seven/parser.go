// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Parser is a parser for L7 payloads
type Parser struct {
	log               logrus.FieldLogger
	timestampCache    *lru.Cache[string, time.Time]
	traceContextCache *lru.Cache[string, *flowpb.TraceContext]
	dnsGetter         getters.DNSGetter
	ipGetter          getters.IPGetter
	serviceGetter     getters.ServiceGetter
	endpointGetter    getters.EndpointGetter
}

// New returns a new L7 parser
func New(
	log logrus.FieldLogger,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	endpointGetter getters.EndpointGetter,
	opts ...options.Option,
) (*Parser, error) {
	args := &options.Options{
		CacheSize: 10000,
	}

	for _, opt := range opts {
		opt(args)
	}

	timestampCache, err := lru.New[string, time.Time](args.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %v", err)
	}

	traceIDCache, err := lru.New[string, *flowpb.TraceContext](args.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %v", err)
	}

	return &Parser{
		log:               log,
		timestampCache:    timestampCache,
		traceContextCache: traceIDCache,
		dnsGetter:         dnsGetter,
		ipGetter:          ipGetter,
		serviceGetter:     serviceGetter,
		endpointGetter:    endpointGetter,
	}, nil
}

// Decode decodes the data from 'payload' into 'decoded'
func (p *Parser) Decode(r *accesslog.LogRecord, decoded *flowpb.Flow) error {
	// Safety: This function and all the helpers it invokes are not allowed to
	// mutate r in any way. We only have read access to the LogRecord, as it
	// may be shared with other consumers
	if r == nil {
		return errors.ErrEmptyData
	}

	timestamp, pbTimestamp, err := decodeTime(r.Timestamp)
	if err != nil {
		return err
	}

	ip := decodeIP(r.IPVersion, r.SourceEndpoint, r.DestinationEndpoint)

	// Ignore IP parsing errors as IPs can be empty. Getters will handle invalid values.
	// Flows with empty IPs have been observed in practice, but it was not clear what kind of flows
	// those are - errors handling here should be revisited once it's clear.
	sourceIP, _ := netip.ParseAddr(ip.Source)
	destinationIP, _ := netip.ParseAddr(ip.Destination)
	var sourceNames, destinationNames []string
	var sourceNamespace, sourcePod, destinationNamespace, destinationPod string
	if p.dnsGetter != nil {
		sourceNames = p.dnsGetter.GetNamesOf(uint32(r.DestinationEndpoint.ID), sourceIP)
		destinationNames = p.dnsGetter.GetNamesOf(uint32(r.SourceEndpoint.ID), destinationIP)
	}
	if p.ipGetter != nil {
		if meta := p.ipGetter.GetK8sMetadata(sourceIP); meta != nil {
			sourceNamespace, sourcePod = meta.Namespace, meta.PodName
		}
		if meta := p.ipGetter.GetK8sMetadata(destinationIP); meta != nil {
			destinationNamespace, destinationPod = meta.Namespace, meta.PodName
		}
	}
	srcEndpoint := decodeEndpoint(r.SourceEndpoint, sourceNamespace, sourcePod)
	dstEndpoint := decodeEndpoint(r.DestinationEndpoint, destinationNamespace, destinationPod)

	if p.endpointGetter != nil {
		p.updateEndpointWorkloads(sourceIP, srcEndpoint)
		p.updateEndpointWorkloads(destinationIP, dstEndpoint)
	}

	l4, sourcePort, destinationPort := decodeLayer4(r.TransportProtocol, r.SourceEndpoint, r.DestinationEndpoint)
	var sourceService, destinationService *flowpb.Service
	if p.serviceGetter != nil {
		sourceService = p.serviceGetter.GetServiceByAddr(sourceIP, sourcePort)
		destinationService = p.serviceGetter.GetServiceByAddr(destinationIP, destinationPort)
	}

	decoded.Time = pbTimestamp
	decoded.Verdict = decodeVerdict(r.Verdict)
	decoded.DropReason = 0
	decoded.DropReasonDesc = flowpb.DropReason_DROP_REASON_UNKNOWN
	decoded.IP = ip
	decoded.L4 = l4
	decoded.Source = srcEndpoint
	decoded.Destination = dstEndpoint
	decoded.Type = flowpb.FlowType_L7
	decoded.SourceNames = sourceNames
	decoded.DestinationNames = destinationNames
	decoded.L7 = decodeLayer7(r)
	decoded.L7.LatencyNs = p.computeResponseTime(r, timestamp)
	decoded.IsReply = decodeIsReply(r.Type)
	decoded.Reply = decoded.GetIsReply().GetValue()
	decoded.EventType = decodeCiliumEventType(api.MessageTypeAccessLog)
	decoded.SourceService = sourceService
	decoded.DestinationService = destinationService
	decoded.TrafficDirection = decodeTrafficDirection(r.ObservationPoint)
	decoded.PolicyMatchType = 0
	decoded.TraceContext = p.getTraceContext(r)
	decoded.Summary = p.getSummary(r, decoded)

	return nil
}

func extractRequestID(r *accesslog.LogRecord) string {
	var requestID string
	if r.HTTP != nil {
		requestID = r.HTTP.Headers.Get("X-Request-Id")
	}
	return requestID
}

func (p *Parser) getTraceContext(r *accesslog.LogRecord) *flowpb.TraceContext {
	requestID := extractRequestID(r)
	switch r.Type {
	case accesslog.TypeRequest:
		traceContext := extractTraceContext(r)
		if traceContext == nil {
			break
		}
		// Envoy should add a requestID to all requests it's managing, but  if it's
		// missing for some reason, don't add to the cache without a requestID.
		if requestID != "" {
			p.traceContextCache.Add(requestID, traceContext)
		}
		return traceContext
	case accesslog.TypeResponse:
		if requestID == "" {
			return nil
		}
		traceContext, ok := p.traceContextCache.Get(requestID)
		if !ok {
			break
		}
		p.traceContextCache.Remove(requestID)
		return traceContext
	}
	return nil
}

func (p *Parser) computeResponseTime(r *accesslog.LogRecord, timestamp time.Time) uint64 {
	requestID := extractRequestID(r)
	if requestID == "" {
		return 0
	}
	switch r.Type {
	case accesslog.TypeRequest:
		p.timestampCache.Add(requestID, timestamp)
	case accesslog.TypeResponse:
		requestTimestamp, ok := p.timestampCache.Get(requestID)
		if !ok {
			return 0
		}
		p.timestampCache.Remove(requestID)
		latency := timestamp.Sub(requestTimestamp).Nanoseconds()
		if latency < 0 {
			return 0
		}
		return uint64(latency)
	}

	return 0
}

func (p *Parser) updateEndpointWorkloads(ip netip.Addr, endpoint *flowpb.Endpoint) {
	if ep, ok := p.endpointGetter.GetEndpointInfo(ip); ok {
		if pod := ep.GetPod(); pod != nil {
			workload, workloadTypeMeta, ok := utils.GetWorkloadMetaFromPod(pod)
			if ok {
				endpoint.Workloads = []*flowpb.Workload{{Kind: workloadTypeMeta.Kind, Name: workload.Name}}
			}
		}
	}
}

func decodeTime(timestamp string) (goTime time.Time, pbTime *timestamppb.Timestamp, err error) {
	goTime, err = time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return
	}

	pbTime = timestamppb.New(goTime)
	err = pbTime.CheckValid()
	return
}

func decodeVerdict(verdict accesslog.FlowVerdict) flowpb.Verdict {
	switch verdict {
	case accesslog.VerdictDenied:
		return flowpb.Verdict_DROPPED
	case accesslog.VerdictForwarded:
		return flowpb.Verdict_FORWARDED
	case accesslog.VerdictRedirected:
		return flowpb.Verdict_REDIRECTED
	case accesslog.VerdictError:
		return flowpb.Verdict_ERROR
	default:
		return flowpb.Verdict_VERDICT_UNKNOWN
	}
}

func decodeTrafficDirection(direction accesslog.ObservationPoint) flowpb.TrafficDirection {
	switch direction {
	case accesslog.Ingress:
		return flowpb.TrafficDirection_INGRESS
	case accesslog.Egress:
		return flowpb.TrafficDirection_EGRESS
	default:
		return flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN
	}
}

func decodeIP(version accesslog.IPVersion, source, destination accesslog.EndpointInfo) *flowpb.IP {
	switch version {
	case accesslog.VersionIPv4:
		return &flowpb.IP{
			Source:      source.IPv4,
			Destination: destination.IPv4,
			IpVersion:   flowpb.IPVersion_IPv4,
		}
	case accesslog.VersionIPV6:
		return &flowpb.IP{
			Source:      source.IPv6,
			Destination: destination.IPv6,
			IpVersion:   flowpb.IPVersion_IPv6,
		}
	default:
		return nil
	}
}

func decodeLayer4(protocol accesslog.TransportProtocol, source, destination accesslog.EndpointInfo) (l4 *flowpb.Layer4, srcPort, dstPort uint16) {
	switch u8proto.U8proto(protocol) {
	case u8proto.TCP:
		return &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      uint32(source.Port),
					DestinationPort: uint32(destination.Port),
				},
			},
		}, uint16(source.Port), uint16(destination.Port)
	case u8proto.UDP:
		return &flowpb.Layer4{
			Protocol: &flowpb.Layer4_UDP{
				UDP: &flowpb.UDP{
					SourcePort:      uint32(source.Port),
					DestinationPort: uint32(destination.Port),
				},
			},
		}, uint16(source.Port), uint16(destination.Port)
	case u8proto.SCTP:
		return &flowpb.Layer4{
			Protocol: &flowpb.Layer4_SCTP{
				SCTP: &flowpb.SCTP{
					SourcePort:      uint32(source.Port),
					DestinationPort: uint32(destination.Port),
				},
			},
		}, uint16(source.Port), uint16(destination.Port)
	default:
		return nil, 0, 0
	}
}

func decodeEndpoint(endpoint accesslog.EndpointInfo, namespace, podName string) *flowpb.Endpoint {
	// Safety: We only have read access to endpoint, therefore we need to create
	// a copy of the label list before we can sort it
	labels := make([]string, len(endpoint.Labels))
	copy(labels, endpoint.Labels)
	sort.Strings(labels)
	return &flowpb.Endpoint{
		ID:        uint32(endpoint.ID),
		Identity:  uint32(endpoint.Identity),
		Namespace: namespace,
		Labels:    labels,
		PodName:   podName,
	}
}

func decodeLayer7(r *accesslog.LogRecord) *flowpb.Layer7 {
	var flowType flowpb.L7FlowType
	switch r.Type {
	case accesslog.TypeRequest:
		flowType = flowpb.L7FlowType_REQUEST
	case accesslog.TypeResponse:
		flowType = flowpb.L7FlowType_RESPONSE
	case accesslog.TypeSample:
		flowType = flowpb.L7FlowType_SAMPLE
	}

	switch {
	case r.DNS != nil:
		return &flowpb.Layer7{
			Type:   flowType,
			Record: decodeDNS(r.Type, r.DNS),
		}
	case r.HTTP != nil:
		return &flowpb.Layer7{
			Type:   flowType,
			Record: decodeHTTP(r.Type, r.HTTP),
		}
	case r.Kafka != nil:
		return &flowpb.Layer7{
			Type:   flowType,
			Record: decodeKafka(r.Type, r.Kafka),
		}
	default:
		return &flowpb.Layer7{
			Type: flowType,
		}
	}
}

func decodeIsReply(t accesslog.FlowType) *wrapperspb.BoolValue {
	return &wrapperspb.BoolValue{
		Value: t == accesslog.TypeResponse,
	}
}

func decodeCiliumEventType(eventType uint8) *flowpb.CiliumEventType {
	return &flowpb.CiliumEventType{
		Type: int32(eventType),
	}
}

func genericSummary(l7 *accesslog.LogRecordL7) string {
	return fmt.Sprintf("%s Fields: %s", l7.Proto, l7.Fields)
}

func (p *Parser) getSummary(logRecord *accesslog.LogRecord, flow *flowpb.Flow) string {
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
