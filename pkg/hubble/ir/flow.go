// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Flow tracks an internal representation of a flow.
// Once created a flow is immutable.
type Flow struct {
	L7                    Layer7                      `json:"l7"`
	L4                    Layer4                      `json:"l4"`
	Source                Endpoint                    `json:"source"`
	Destination           Endpoint                    `json:"destination"`
	Emitter               Emitter                     `json:"emitter"`
	Ethernet              Ethernet                    `json:"ethernet"`
	IP                    IP                          `json:"ip"`
	SourceService         Service                     `json:"sourceService"`
	DestinationService    Service                     `json:"destinationService"`
	File                  FileInfo                    `json:"file"`
	Interface             NetworkInterface            `json:"interface"`
	TraceContext          TraceContext                `json:"traceContext"`
	CreatedOn             time.Time                   `json:"createdOn"`
	NodeLabels            []string                    `json:"nodeLabels,omitempty"`
	SourceNames           []string                    `json:"sourceNames,omitempty"`
	DestinationNames      []string                    `json:"destinationNames,omitempty"`
	Extensions            []any                       `json:"extensions,omitempty"`
	EgressAllowedBy       []Policy                    `json:"egressAllowedBy,omitempty"`
	EgressDeniedBy        []Policy                    `json:"egressDeniedBy,omitempty"`
	IngressAllowedBy      []Policy                    `json:"ingressAllowedBy,omitempty"`
	IngressDeniedBy       []Policy                    `json:"ingressDeniedBy,omitempty"`
	PolicyLog             []string                    `json:"policyLog,omitempty"`
	UUID                  string                      `json:"uuid,omitempty"`
	NodeName              string                      `json:"nodeName,omitempty"`
	Summary               string                      `json:"summary,omitempty"`
	Tunnel                Tunnel                      `json:"tunnel"`
	IPTraceID             IPTraceID                   `json:"ipTraceId"`
	EventType             EventType                   `json:"eventType"`
	Aggregate             Aggregate                   `json:"aggregate"`
	SocketCookie          uint64                      `json:"socketCookie,omitempty"`
	CgroupID              uint64                      `json:"cgroupID,omitempty"`
	PolicyMatchType       uint32                      `json:"policyMatchType,omitempty"`
	ProxyPort             uint32                      `json:"proxyPort,omitempty"`
	DropReason            uint32                      `json:"dropReason,omitempty"`
	AuthType              flow.AuthType               `json:"authType,omitempty"`
	Verdict               flow.Verdict                `json:"verdict,omitempty"`
	DropReasonDesc        flow.DropReason             `json:"dropReasonDesc,omitempty"`
	TrafficDirection      flow.TrafficDirection       `json:"trafficDirection,omitempty"`
	TraceObservationPoint flow.TraceObservationPoint  `json:"traceObservationPoint,omitempty"`
	TraceReason           flow.TraceReason            `json:"traceReason,omitempty"`
	DebugCapturePoint     flow.DebugCapturePoint      `json:"debugCapturePoint,omitempty"`
	SockXlatePoint        flow.SocketTranslationPoint `json:"sockXlatePoint,omitempty"`
	Type                  flow.FlowType               `json:"type,omitempty"`
	Reply                 Reply                       `json:"reply,omitempty"`
}

// Clone returns a new copy.
func (f *Flow) Clone() Flow {

	if f == nil {
		return Flow{}
	}

	return Flow{
		CreatedOn:             f.CreatedOn,
		UUID:                  f.UUID,
		Emitter:               f.Emitter,
		Verdict:               f.Verdict,
		AuthType:              f.AuthType,
		Ethernet:              f.Ethernet,
		IP:                    f.IP,
		L4:                    f.L4,
		Tunnel:                f.Tunnel,
		Source:                f.Source,
		Destination:           f.Destination,
		Type:                  f.Type,
		NodeName:              f.NodeName,
		NodeLabels:            f.NodeLabels,
		SourceNames:           f.SourceNames,
		DestinationNames:      f.DestinationNames,
		L7:                    f.L7,
		EventType:             f.EventType,
		SourceService:         f.SourceService,
		DestinationService:    f.DestinationService,
		TrafficDirection:      f.TrafficDirection,
		PolicyMatchType:       f.PolicyMatchType,
		TraceObservationPoint: f.TraceObservationPoint,
		TraceReason:           f.TraceReason,
		File:                  f.File,
		IPTraceID:             f.IPTraceID,
		DropReasonDesc:        f.DropReasonDesc,
		DropReason:            f.DropReason,
		Reply:                 f.Reply,
		DebugCapturePoint:     f.DebugCapturePoint,
		Interface:             f.Interface,
		ProxyPort:             f.ProxyPort,
		TraceContext:          f.TraceContext,
		SockXlatePoint:        f.SockXlatePoint,
		SocketCookie:          f.SocketCookie,
		CgroupID:              f.CgroupID,
		Summary:               f.Summary,
		Extensions:            f.Extensions,
		EgressAllowedBy:       f.EgressAllowedBy,
		EgressDeniedBy:        f.EgressDeniedBy,
		IngressAllowedBy:      f.IngressAllowedBy,
		IngressDeniedBy:       f.IngressDeniedBy,
		PolicyLog:             f.PolicyLog,
		Aggregate:             f.Aggregate,
	}
}

// ProtoToFlow converts a protobuf flow to an internal representation.
func ProtoToFlow(fl *flow.Flow) *Flow {
	if fl == nil {
		return nil
	}

	var f Flow
	if fl.Time != nil {
		f.CreatedOn = fl.GetTime().AsTime()
	}
	f.UUID = fl.GetUuid()
	f.Emitter = protoToEmitter(fl.Emitter)
	f.Verdict = fl.GetVerdict()
	f.AuthType = fl.GetAuthType()
	f.Ethernet = protoToEther(fl.GetEthernet())
	f.IP = protoToIP(fl.GetIP())
	f.L4 = protoToL4(fl.GetL4())
	f.L7 = protoToL7(fl.GetL7())
	f.Tunnel = protoToTunnel(fl.GetTunnel())
	f.Source = ProtoToEp(fl.GetSource())
	f.Destination = ProtoToEp(fl.GetDestination())
	f.Type = fl.GetType()
	f.NodeName = fl.GetNodeName()
	f.NodeLabels = fl.GetNodeLabels()
	f.SourceNames = fl.GetSourceNames()
	f.DestinationNames = fl.GetDestinationNames()
	f.EventType = ProtoToEventType(fl.GetEventType())
	f.SourceService = ProtoToService(fl.GetSourceService())
	f.DestinationService = ProtoToService(fl.GetDestinationService())
	f.TrafficDirection = fl.GetTrafficDirection()
	f.PolicyMatchType = fl.GetPolicyMatchType()
	f.TraceObservationPoint = fl.GetTraceObservationPoint()
	f.TraceReason = fl.GetTraceReason()
	f.File = protoToFileInfo(fl.GetFile())
	f.IPTraceID = ProtoToIPTraceID(fl.GetIpTraceId())
	f.DropReasonDesc = fl.GetDropReasonDesc()
	f.DropReason = fl.GetDropReason()
	if b := fl.IsReply; b == nil {
		f.Reply = ReplyUnknown
	} else if b.Value {
		f.Reply = ReplyYes
	} else {
		f.Reply = ReplyNo
	}
	f.DebugCapturePoint = fl.GetDebugCapturePoint()
	f.Interface = ProtoToNetworkInterface(fl.GetInterface())
	f.ProxyPort = fl.GetProxyPort()
	f.TraceContext = ProtoToTraceContext(fl.GetTraceContext())
	f.SockXlatePoint = fl.GetSockXlatePoint()
	f.SocketCookie = fl.GetSocketCookie()
	f.CgroupID = fl.GetCgroupId()
	f.Summary = fl.GetSummary()

	return &f
}

// ToProto converts a flow internal representation to a protobuf flow.
func (f *Flow) ToProto() *flow.Flow {
	var fl flow.Flow

	fl.Time = timestamppb.New(f.CreatedOn)
	fl.Uuid = f.UUID
	fl.Emitter = f.Emitter.toProto()
	fl.Verdict = f.Verdict
	fl.AuthType = f.AuthType
	fl.Ethernet = f.Ethernet.toProto()
	fl.IP = f.IP.toProto()
	fl.L4 = f.L4.toProto()
	fl.L7 = f.L7.toProto()
	fl.Tunnel = f.Tunnel.toProto()
	fl.Source = f.Source.toProto()
	fl.Destination = f.Destination.toProto()
	fl.Type = f.Type
	fl.NodeName = f.NodeName
	fl.NodeLabels = f.NodeLabels
	fl.SourceNames = f.SourceNames
	fl.DestinationNames = f.DestinationNames
	fl.EventType = f.EventType.toProto()
	fl.SourceService = f.SourceService.toProto()
	fl.DestinationService = f.DestinationService.toProto()
	fl.TrafficDirection = f.TrafficDirection
	fl.PolicyMatchType = f.PolicyMatchType
	fl.TraceObservationPoint = f.TraceObservationPoint
	fl.TraceReason = f.TraceReason
	fl.File = f.File.toProto()
	fl.IpTraceId = f.IPTraceID.toProto()
	fl.DropReasonDesc = f.DropReasonDesc
	fl.DropReason = f.DropReason
	fl.IsReply = f.Reply.toProto()
	fl.DebugCapturePoint = f.DebugCapturePoint
	fl.Interface = f.Interface.toProto()
	fl.ProxyPort = f.ProxyPort
	fl.TraceContext = f.TraceContext.toProto()
	fl.SockXlatePoint = f.SockXlatePoint
	fl.SocketCookie = f.SocketCookie
	fl.CgroupId = f.CgroupID
	fl.Summary = f.Summary

	return &fl
}

// Merge merges two flows.
// !!BOZO!! Testing only!
func (f *Flow) Merge(f1 *Flow) *Flow {
	if f1 == nil {
		return f
	}
	if f == nil {
		return f1
	}

	f.CreatedOn = f1.CreatedOn
	f.UUID = f1.UUID
	f.Verdict = f1.Verdict
	f.AuthType = f1.AuthType
	f.IP = f.IP.merge(f1.IP)

	if !f1.Emitter.isEmpty() {
		f.Emitter = f1.Emitter
	}
	if !f1.Ethernet.isEmpty() {
		f.Ethernet = f1.Ethernet
	}
	if !f1.L4.IsEmpty() {
		f.L4 = f1.L4
	}
	if !f1.L7.IsEmpty() {
		f.L7 = f1.L7
	}

	if !f1.Tunnel.isEmpty() {
		f.Tunnel = f1.Tunnel
	}

	if !f1.Source.IsEmpty() {
		f.Source = f.Source.merge(f1.Source)
	}
	if !f1.Destination.IsEmpty() {
		f.Destination = f.Destination.merge(f1.Destination)
	}

	if f1.Type != flow.FlowType_UNKNOWN_TYPE {
		f.Type = f1.Type
	}

	if f1.NodeName != "" {
		f.NodeName = f1.NodeName
	}
	if len(f1.NodeLabels) > 0 {
		f.NodeLabels = f1.NodeLabels
	}

	if f1.SourceNames != nil {
		f.SourceNames = f1.SourceNames
	}
	if f1.DestinationNames != nil {
		f.DestinationNames = f1.DestinationNames
	}

	if !f1.EventType.IsEmpty() {
		f.EventType = f1.EventType
		f.EventType.SubType = f1.EventType.SubType
	}

	if !f1.SourceService.isEmpty() {
		f.SourceService = f1.SourceService
	}
	if !f1.DestinationService.isEmpty() {
		f.DestinationService = f1.DestinationService
	}

	if f1.TrafficDirection != flow.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN {
		f.TrafficDirection = f1.TrafficDirection
	}

	if f1.PolicyMatchType != 0 {
		f.PolicyMatchType = f1.PolicyMatchType
	}

	if f1.TraceObservationPoint != flow.TraceObservationPoint_UNKNOWN_POINT {
		f.TraceObservationPoint = f1.TraceObservationPoint
	}
	if f1.TraceReason != flow.TraceReason_TRACE_REASON_UNKNOWN {
		f.TraceReason = f1.TraceReason
	}
	if f1.IPTraceID.TraceID != 0 {
		f.IPTraceID = f1.IPTraceID
	}

	if !f1.File.isEmpty() {
		f.File = f1.File
	}

	if f1.DropReasonDesc != flow.DropReason_DROP_REASON_UNKNOWN {
		f.DropReasonDesc = f1.DropReasonDesc
	}
	if f1.DropReason != 0 {
		f.DropReason = f1.DropReason
	}

	if f1.Reply != ReplyUnknown {
		f.Reply = f1.Reply
	}

	if f1.DebugCapturePoint != flow.DebugCapturePoint_DBG_CAPTURE_POINT_UNKNOWN {
		f.DebugCapturePoint = f1.DebugCapturePoint
	}

	if !f1.Interface.IsEmpty() {
		f.Interface = f1.Interface
	}

	if f1.ProxyPort != 0 {
		f.ProxyPort = f1.ProxyPort
	}

	if !f1.TraceContext.isEmpty() {
		f.TraceContext = f1.TraceContext
	}

	if f1.SockXlatePoint != flow.SocketTranslationPoint_SOCK_XLATE_POINT_UNKNOWN {
		f.SockXlatePoint = f1.SockXlatePoint
	}

	if f1.SocketCookie != 0 {
		f.SocketCookie = f1.SocketCookie
	}

	if f1.CgroupID != 0 {
		f.CgroupID = f1.CgroupID
	}

	if f1.Summary != "" {
		f.Summary = f1.Summary
	}

	if len(f1.Extensions) > 0 {
		f.Extensions = f1.Extensions
	}

	if len(f1.EgressAllowedBy) > 0 {
		f.EgressAllowedBy = f1.EgressAllowedBy
	}
	if len(f1.EgressDeniedBy) > 0 {
		f.EgressDeniedBy = f1.EgressDeniedBy
	}
	if len(f1.IngressAllowedBy) > 0 {
		f.IngressAllowedBy = f1.IngressAllowedBy
	}
	if len(f1.IngressDeniedBy) > 0 {
		f.IngressDeniedBy = f1.IngressDeniedBy
	}

	if len(f1.PolicyLog) > 0 {
		f.PolicyLog = f1.PolicyLog
	}

	if f1.Aggregate.IngressFlowCount != 0 || f1.Aggregate.EgressFlowCount != 0 {
		f.Aggregate = f1.Aggregate
	}

	return f
}

// IsReply returns true if the flow is a reply.
func (f *Flow) IsReply() bool {
	if f != nil {
		return f.Reply == ReplyYes
	}

	return false
}
