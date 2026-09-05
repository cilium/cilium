// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Flow tracks an internal representation of a flow.
type Flow struct {
	L7                    Layer7                      `json:"l7,omitempty"`
	L4                    Layer4                      `json:"l4,omitempty"`
	Source                Endpoint                    `json:"source,omitempty"`
	Destination           Endpoint                    `json:"destination,omitempty"`
	Emitter               Emitter                     `json:"emitter,omitempty"`
	Ethernet              Ethernet                    `json:"ethernet,omitempty"`
	IP                    IP                          `json:"ip,omitempty"`
	SourceService         Service                     `json:"source_service,omitempty"`
	DestinationService    Service                     `json:"destination_service,omitempty"`
	File                  FileInfo                    `json:"file,omitempty"`
	Interface             NetworkInterface            `json:"interface,omitempty"`
	TraceContext          TraceContext                `json:"trace_context,omitempty"`
	Time                  time.Time                   `json:"time,omitempty"`
	NodeLabels            []string                    `json:"node_labels,omitempty"`
	SourceNames           []string                    `json:"source_names,omitempty"`
	DestinationNames      []string                    `json:"destination_names,omitempty"`
	Extensions            *anypb.Any                  `json:"extensions,omitempty"`
	EgressAllowedBy       []Policy                    `json:"egress_allowed_by,omitempty"`
	EgressDeniedBy        []Policy                    `json:"egress_denied_by,omitempty"`
	IngressAllowedBy      []Policy                    `json:"ingress_allowed_by,omitempty"`
	IngressDeniedBy       []Policy                    `json:"ingress_denied_by,omitempty"`
	PolicyLog             []string                    `json:"policy_log,omitempty"`
	UUID                  string                      `json:"uuid,omitempty"`
	NodeName              string                      `json:"node_name,omitempty"`
	Summary               string                      `json:"summary,omitempty"`
	Tunnel                Tunnel                      `json:"tunnel,omitempty"`
	IPTraceID             IPTraceID                   `json:"ip_trace_id,omitempty"`
	EventType             CiliumEventType             `json:"event_type,omitempty"`
	Aggregate             Aggregate                   `json:"aggregate,omitempty"`
	SocketCookie          uint64                      `json:"socket_cookie,omitempty"`
	CgroupID              uint64                      `json:"cgroup_id,omitempty"`
	PolicyMatchType       uint32                      `json:"policy_match_type,omitempty"`
	ProxyPort             uint32                      `json:"proxy_port,omitempty"`
	DropReason            uint32                      `json:"drop_reason,omitempty"`
	ExtError              int32                       `json:"ext_error,omitempty"`
	ExtDropReasonDesc     string                      `json:"ext_drop_reason_desc,omitempty"`
	AuthType              flow.AuthType               `json:"auth_type,omitempty"`
	Verdict               flow.Verdict                `json:"verdict,omitempty"`
	DropReasonDesc        flow.DropReason             `json:"drop_reason_desc,omitempty"`
	TrafficDirection      flow.TrafficDirection       `json:"traffic_direction,omitempty"`
	TraceObservationPoint flow.TraceObservationPoint  `json:"trace_observation_point,omitempty"`
	TraceReason           flow.TraceReason            `json:"trace_reason,omitempty"`
	DebugCapturePoint     flow.DebugCapturePoint      `json:"debug_capture_point,omitempty"`
	SockXlatePoint        flow.SocketTranslationPoint `json:"sock_xlate_point,omitempty"`
	Type                  flow.FlowType               `json:"type,omitempty"`
	Reply                 Reply                       `json:"reply,omitempty"`
}

// Clone returns a new copy.
func (f *Flow) Clone() Flow {
	if f == nil {
		return Flow{}
	}

	return Flow{
		L7:                    f.L7,
		L4:                    f.L4,
		Source:                f.Source,
		Destination:           f.Destination,
		Emitter:               f.Emitter,
		Ethernet:              f.Ethernet,
		IP:                    f.IP,
		SourceService:         f.SourceService,
		DestinationService:    f.DestinationService,
		File:                  f.File,
		Interface:             f.Interface,
		TraceContext:          f.TraceContext,
		Time:                  f.Time,
		NodeLabels:            f.NodeLabels,
		SourceNames:           f.SourceNames,
		DestinationNames:      f.DestinationNames,
		Extensions:            f.Extensions,
		EgressAllowedBy:       f.EgressAllowedBy,
		EgressDeniedBy:        f.EgressDeniedBy,
		IngressAllowedBy:      f.IngressAllowedBy,
		IngressDeniedBy:       f.IngressDeniedBy,
		PolicyLog:             f.PolicyLog,
		UUID:                  f.UUID,
		NodeName:              f.NodeName,
		Summary:               f.Summary,
		Tunnel:                f.Tunnel,
		IPTraceID:             f.IPTraceID,
		EventType:             f.EventType,
		SocketCookie:          f.SocketCookie,
		CgroupID:              f.CgroupID,
		PolicyMatchType:       f.PolicyMatchType,
		ProxyPort:             f.ProxyPort,
		DropReason:            f.DropReason,
		ExtError:              f.ExtError,
		ExtDropReasonDesc:     f.ExtDropReasonDesc,
		AuthType:              f.AuthType,
		Verdict:               f.Verdict,
		DropReasonDesc:        f.DropReasonDesc,
		TrafficDirection:      f.TrafficDirection,
		TraceObservationPoint: f.TraceObservationPoint,
		TraceReason:           f.TraceReason,
		DebugCapturePoint:     f.DebugCapturePoint,
		SockXlatePoint:        f.SockXlatePoint,
		Aggregate:             f.Aggregate,
		Type:                  f.Type,
		Reply:                 f.Reply,
	}
}

// ProtoToFlow converts a protobuf flow to an internal representation.
func ProtoToFlow(fl *flow.Flow) *Flow {
	if fl == nil {
		return nil
	}

	f := Flow{
		L7:                    protoToL7(fl.GetL7()),
		L4:                    protoToL4(fl.GetL4()),
		Source:                ProtoToEp(fl.GetSource()),
		Destination:           ProtoToEp(fl.GetDestination()),
		Emitter:               protoToEmitter(fl.GetEmitter()),
		Ethernet:              protoToEther(fl.GetEthernet()),
		SourceService:         ProtoToService(fl.GetSourceService()),
		IP:                    protoToIP(fl.GetIP()),
		DestinationService:    ProtoToService(fl.GetDestinationService()),
		File:                  protoToFileInfo(fl.GetFile()),
		Interface:             ProtoToNetworkInterface(fl.GetInterface()),
		TraceContext:          ProtoToTraceContext(fl.GetTraceContext()),
		NodeLabels:            fl.GetNodeLabels(),
		SourceNames:           fl.GetSourceNames(),
		DestinationNames:      fl.GetDestinationNames(),
		Extensions:            fl.GetExtensions(),
		EgressAllowedBy:       protoToPolicies(fl.GetEgressAllowedBy()),
		EgressDeniedBy:        protoToPolicies(fl.GetEgressDeniedBy()),
		IngressAllowedBy:      protoToPolicies(fl.GetIngressAllowedBy()),
		IngressDeniedBy:       protoToPolicies(fl.GetIngressDeniedBy()),
		PolicyLog:             fl.GetPolicyLog(),
		UUID:                  fl.GetUuid(),
		NodeName:              fl.GetNodeName(),
		Summary:               fl.GetSummary(),
		Tunnel:                protoToTunnel(fl.GetTunnel()),
		IPTraceID:             ProtoToIPTraceID(fl.GetIpTraceId()),
		EventType:             ProtoToEventType(fl.GetEventType()),
		Aggregate:             ProtoToAggregate(fl.GetAggregate()),
		SocketCookie:          fl.GetSocketCookie(),
		CgroupID:              fl.GetCgroupId(),
		PolicyMatchType:       fl.GetPolicyMatchType(),
		ProxyPort:             fl.GetProxyPort(),
		DropReason:            fl.GetDropReason(),
		ExtError:              fl.GetExtError(),
		ExtDropReasonDesc:     fl.GetExtDropReasonDesc(),
		AuthType:              fl.GetAuthType(),
		Verdict:               fl.GetVerdict(),
		DropReasonDesc:        fl.GetDropReasonDesc(),
		TrafficDirection:      fl.GetTrafficDirection(),
		TraceObservationPoint: fl.GetTraceObservationPoint(),
		TraceReason:           fl.GetTraceReason(),
		DebugCapturePoint:     fl.GetDebugCapturePoint(),
		SockXlatePoint:        fl.GetSockXlatePoint(),
		Type:                  fl.GetType(),
		Reply:                 ProtoToReply(fl.IsReply),
	}

	if ti := fl.Time; ti != nil {
		t := ti.AsTime()
		if !t.IsZero() {
			f.Time = t
		}
	}

	return &f
}

// ToProto converts a flow internal representation to a protobuf flow.
func (f *Flow) ToProto() *flow.Flow {
	fl := flow.Flow{
		L7:                    f.L7.toProto(),
		L4:                    f.L4.toProto(),
		Source:                f.Source.toProto(),
		Destination:           f.Destination.toProto(),
		Emitter:               f.Emitter.toProto(),
		Ethernet:              f.Ethernet.toProto(),
		IP:                    f.IP.toProto(),
		SourceService:         f.SourceService.toProto(),
		DestinationService:    f.DestinationService.toProto(),
		File:                  f.File.toProto(),
		Interface:             f.Interface.toProto(),
		TraceContext:          f.TraceContext.toProto(),
		NodeLabels:            f.NodeLabels,
		SourceNames:           f.SourceNames,
		DestinationNames:      f.DestinationNames,
		Extensions:            f.Extensions,
		EgressAllowedBy:       policiesToProto(f.EgressAllowedBy),
		EgressDeniedBy:        policiesToProto(f.EgressDeniedBy),
		IngressAllowedBy:      policiesToProto(f.IngressAllowedBy),
		IngressDeniedBy:       policiesToProto(f.IngressDeniedBy),
		PolicyLog:             f.PolicyLog,
		NodeName:              f.NodeName,
		Summary:               f.Summary,
		Tunnel:                f.Tunnel.toProto(),
		IpTraceId:             f.IPTraceID.toProto(),
		EventType:             f.EventType.toProto(),
		Aggregate:             f.Aggregate.toProto(),
		SocketCookie:          f.SocketCookie,
		CgroupId:              f.CgroupID,
		PolicyMatchType:       f.PolicyMatchType,
		ProxyPort:             f.ProxyPort,
		DropReason:            f.DropReason,
		AuthType:              f.AuthType,
		Verdict:               f.Verdict,
		DropReasonDesc:        f.DropReasonDesc,
		ExtError:              f.ExtError,
		ExtDropReasonDesc:     f.ExtDropReasonDesc,
		TrafficDirection:      f.TrafficDirection,
		TraceObservationPoint: f.TraceObservationPoint,
		TraceReason:           f.TraceReason,
		DebugCapturePoint:     f.DebugCapturePoint,
		SockXlatePoint:        f.SockXlatePoint,
		Type:                  f.Type,
		IsReply:               f.Reply.toProto(),
		Reply:                 f.Reply.ToBool(),
	}

	if !f.Time.IsZero() {
		fl.Time = timestamppb.New(f.Time)
	}

	return &fl
}

// IsReply returns true if the flow is a reply.
func (f *Flow) IsReply() bool {
	if f != nil {
		return f.Reply == ReplyYes
	}

	return false
}

// TestMerge merges two flows.
// NOTE: Do not use!! This is for testing purposes only.
func TestMerge(f1, f2 *Flow) *Flow {
	if f1 == nil {
		return f2
	}
	if f2 == nil {
		return f1
	}

	if !f2.L7.IsEmpty() {
		f1.L7 = f2.L7
	}
	if !f2.L4.IsEmpty() {
		f1.L4 = f2.L4
	}

	if !f2.Source.IsEmpty() {
		f1.Source = epTestMerge(f1.Source, f2.Source)
	}
	if !f2.Destination.IsEmpty() {
		f1.Destination = epTestMerge(f1.Destination, f2.Destination)
	}

	if !f2.Emitter.IsEmpty() {
		f1.Emitter = f2.Emitter
	}

	if !f2.Ethernet.IsEmpty() {
		f1.Ethernet = f2.Ethernet
	}

	f1.IP = ipTestMerge(f1.IP, f2.IP)

	if !f2.SourceService.IsEmpty() {
		f1.SourceService = f2.SourceService
	}
	if !f2.DestinationService.IsEmpty() {
		f1.DestinationService = f2.DestinationService
	}

	if !f2.File.IsEmpty() {
		f1.File = f2.File
	}

	if !f2.Interface.IsEmpty() {
		f1.Interface = f2.Interface
	}

	if !f2.TraceContext.IsEmpty() {
		f1.TraceContext = f2.TraceContext
	}

	f1.Time = f2.Time

	if len(f2.NodeLabels) > 0 {
		f1.NodeLabels = f2.NodeLabels
	}

	if f2.SourceNames != nil {
		f1.SourceNames = f2.SourceNames
	}
	if f2.DestinationNames != nil {
		f1.DestinationNames = f2.DestinationNames
	}

	if f2.Extensions != nil {
		f1.Extensions = f2.Extensions
	}

	if len(f2.EgressAllowedBy) > 0 {
		f1.EgressAllowedBy = f2.EgressAllowedBy
	}
	if len(f2.EgressDeniedBy) > 0 {
		f1.EgressDeniedBy = f2.EgressDeniedBy
	}
	if len(f2.IngressAllowedBy) > 0 {
		f1.IngressAllowedBy = f2.IngressAllowedBy
	}
	if len(f2.IngressDeniedBy) > 0 {
		f1.IngressDeniedBy = f2.IngressDeniedBy
	}

	if len(f2.PolicyLog) > 0 {
		f1.PolicyLog = f2.PolicyLog
	}

	f1.UUID = f2.UUID

	if f2.NodeName != "" {
		f1.NodeName = f2.NodeName
	}

	if f2.Summary != "" {
		f1.Summary = f2.Summary
	}

	if !f2.Tunnel.IsEmpty() {
		f1.Tunnel = f2.Tunnel
	}

	f1.IPTraceID = f2.IPTraceID

	if !f2.EventType.IsEmpty() {
		f1.EventType = f2.EventType
		f1.EventType.SubType = f2.EventType.SubType
	}

	f1.Aggregate = f2.Aggregate
	f1.SocketCookie = f2.SocketCookie
	f1.CgroupID = f2.CgroupID
	f1.PolicyMatchType = f2.PolicyMatchType
	f1.ProxyPort = f2.ProxyPort
	f1.DropReason = f2.DropReason
	f1.ExtError = f2.ExtError
	f1.ExtDropReasonDesc = f2.ExtDropReasonDesc
	f1.AuthType = f2.AuthType
	f1.Verdict = f2.Verdict
	f1.DropReasonDesc = f2.DropReasonDesc
	f1.TrafficDirection = f2.TrafficDirection

	if f2.TraceObservationPoint != flow.TraceObservationPoint_UNKNOWN_POINT {
		f1.TraceObservationPoint = f2.TraceObservationPoint
	}

	f1.TraceReason = f2.TraceReason
	f1.DebugCapturePoint = f2.DebugCapturePoint

	if f2.SockXlatePoint != flow.SocketTranslationPoint_SOCK_XLATE_POINT_UNKNOWN {
		f1.SockXlatePoint = f2.SockXlatePoint
	}

	if f2.Type != flow.FlowType_UNKNOWN_TYPE {
		f1.Type = f2.Type
	}

	if f2.Reply != ReplyUnknown {
		f1.Reply = f2.Reply
	}

	return f1
}

func (f *Flow) GetEgressAllowedBy() []Policy {
	return f.EgressAllowedBy
}

func (f *Flow) GetEgressDeniedBy() []Policy {
	return f.EgressDeniedBy
}

func (f *Flow) GetIngressAllowedBy() []Policy {
	return f.IngressAllowedBy
}

func (f *Flow) GetIngressDeniedBy() []Policy {
	return f.IngressDeniedBy
}
