// Copyright 2019-2021 Authors of Hubble
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

package printer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Printer for flows.
type Printer struct {
	opts        Options
	line        int
	tw          *tabwriter.Writer
	jsonEncoder *json.Encoder
	color       *colorer
}

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) write(a ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprint(ew.w, a...)
}

func (ew *errWriter) writef(format string, a ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

// New Printer.
func New(fopts ...Option) *Printer {
	// default options
	opts := Options{
		output:     TabOutput,
		w:          os.Stdout,
		werr:       os.Stderr,
		timeFormat: time.StampMilli,
	}

	// apply optional parameters
	for _, fopt := range fopts {
		fopt(&opts)
	}

	p := &Printer{
		opts:  opts,
		color: newColorer(opts.color),
	}

	switch opts.output {
	case TabOutput:
		// initialize tabwriter since it's going to be needed
		p.tw = tabwriter.NewWriter(opts.w, 2, 0, 3, ' ', 0)
		p.color.disable() // the tabwriter is not compatible with colors, thus disable coloring
	case JSONOutput, JSONPBOutput:
		p.jsonEncoder = json.NewEncoder(p.opts.w)
	}

	return p
}

const (
	tab     = "\t"
	newline = "\n"
	space   = " "

	dictSeparator = "------------"

	nodeNamesCutOff = 50
)

// Close any outstanding operations going on in the printer.
func (p *Printer) Close() error {
	if p.tw != nil {
		return p.tw.Flush()
	}

	return nil
}

// WriteErr returns the given msg into the err writer defined in the printer.
func (p *Printer) WriteErr(msg string) error {
	_, err := fmt.Fprintln(p.opts.werr, msg)
	return err
}

// GetPorts returns source and destination port of a flow.
func (p *Printer) GetPorts(f *pb.Flow) (string, string) {
	l4 := f.GetL4()
	if l4 == nil {
		return "", ""
	}
	switch l4.Protocol.(type) {
	case *pb.Layer4_TCP:
		return strconv.Itoa(int(l4.GetTCP().SourcePort)), strconv.Itoa(int(l4.GetTCP().DestinationPort))
	case *pb.Layer4_UDP:
		return strconv.Itoa(int(l4.GetUDP().SourcePort)), strconv.Itoa(int(l4.GetUDP().DestinationPort))
	default:
		return "", ""
	}
}

// GetHostNames returns source and destination hostnames of a flow.
func (p *Printer) GetHostNames(f *pb.Flow) (string, string) {
	var srcNamespace, dstNamespace, srcPodName, dstPodName, srcSvcName, dstSvcName string
	if f == nil {
		return "", ""
	}

	if f.GetIP() == nil {
		if eth := f.GetEthernet(); eth != nil {
			return p.color.host(eth.GetSource()), p.color.host(eth.GetDestination())
		}
		return "", ""
	}

	if src := f.GetSource(); src != nil {
		srcNamespace = src.Namespace
		srcPodName = src.PodName
	}
	if dst := f.GetDestination(); dst != nil {
		dstNamespace = dst.Namespace
		dstPodName = dst.PodName
	}
	if svc := f.GetSourceService(); svc != nil {
		srcNamespace = svc.Namespace
		srcSvcName = svc.Name
	}
	if svc := f.GetDestinationService(); svc != nil {
		dstNamespace = svc.Namespace
		dstSvcName = svc.Name
	}
	srcPort, dstPort := p.GetPorts(f)
	src := p.Hostname(f.GetIP().Source, srcPort, srcNamespace, srcPodName, srcSvcName, f.GetSourceNames())
	dst := p.Hostname(f.GetIP().Destination, dstPort, dstNamespace, dstPodName, dstSvcName, f.GetDestinationNames())
	return p.color.host(src), p.color.host(dst)
}

func (p *Printer) fmtIdentity(i uint32) string {
	numeric := identity.NumericIdentity(i)
	if numeric.IsReservedIdentity() {
		return p.color.identity(fmt.Sprintf("(%s)", numeric))
	}

	return p.color.identity(fmt.Sprintf("(ID:%d)", i))
}

// GetSecurityIdentities returns the source and destination numeric security
// identity formatted as a string.
func (p *Printer) GetSecurityIdentities(f *pb.Flow) (srcIdentity, dstIdentity string) {
	if f == nil {
		return "", ""
	}

	srcIdentity = p.fmtIdentity(f.GetSource().GetIdentity())
	dstIdentity = p.fmtIdentity(f.GetDestination().GetIdentity())

	return srcIdentity, dstIdentity
}

func fmtTimestamp(layout string, ts *timestamppb.Timestamp) string {
	if !ts.IsValid() {
		return "N/A"
	}
	return ts.AsTime().Format(layout)
}

// GetFlowType returns the type of a flow as a string.
func GetFlowType(f *pb.Flow) string {
	if l7 := f.GetL7(); l7 != nil {
		l7Protocol := "l7"
		l7Type := strings.ToLower(l7.Type.String())
		switch l7.GetRecord().(type) {
		case *pb.Layer7_Http:
			l7Protocol = "http"
		case *pb.Layer7_Dns:
			l7Protocol = "dns"
		case *pb.Layer7_Kafka:
			l7Protocol = "kafka"
		}
		return l7Protocol + "-" + l7Type
	}

	switch f.GetEventType().GetType() {
	case api.MessageTypeTrace:
		return api.TraceObservationPoint(uint8(f.GetEventType().GetSubType()))
	case api.MessageTypeDrop:
		return api.DropReason(uint8(f.GetEventType().GetSubType()))
	case api.MessageTypePolicyVerdict:
		return api.MessageTypeNamePolicyVerdict + ":" + api.PolicyMatchType(f.GetPolicyMatchType()).String()
	case api.MessageTypeCapture:
		return f.GetDebugCapturePoint().String()
	}

	return "UNKNOWN"
}

func (p Printer) getVerdict(f *pb.Flow) string {
	verdict := f.GetVerdict()
	msg := verdict.String()
	switch verdict {
	case pb.Verdict_FORWARDED, pb.Verdict_REDIRECTED:
		if f.GetEventType().GetType() == api.MessageTypePolicyVerdict {
			msg = "ALLOWED"
		}
		return p.color.verdictForwarded(msg)
	case pb.Verdict_DROPPED, pb.Verdict_ERROR:
		if f.GetEventType().GetType() == api.MessageTypePolicyVerdict {
			msg = "DENIED"
		}
		return p.color.verdictDropped(msg)
	case pb.Verdict_AUDIT:
		if f.GetEventType().GetType() == api.MessageTypePolicyVerdict {
			msg = "AUDITED"
		}
		return p.color.verdictAudit(msg)
	default:
		return msg
	}
}

// WriteProtoFlow writes v1.Flow into the output writer.
func (p *Printer) WriteProtoFlow(res *observerpb.GetFlowsResponse) error {
	f := res.GetFlow()

	switch p.opts.output {
	case TabOutput:
		ew := &errWriter{w: p.tw}
		src, dst := p.GetHostNames(f)

		if p.line == 0 {
			ew.write("TIMESTAMP", tab)
			if p.opts.nodeName {
				ew.write("NODE", tab)
			}
			ew.write(
				"SOURCE", tab,
				"DESTINATION", tab,
				"TYPE", tab,
				"VERDICT", tab,
				"SUMMARY", newline,
			)
		}
		ew.write(fmtTimestamp(p.opts.timeFormat, f.GetTime()), tab)
		if p.opts.nodeName {
			ew.write(f.GetNodeName(), tab)
		}
		ew.write(
			src, tab,
			dst, tab,
			GetFlowType(f), tab,
			p.getVerdict(f), tab,
			f.GetSummary(), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out packet: %v", ew.err)
		}
	case DictOutput:
		ew := &errWriter{w: p.opts.w}
		src, dst := p.GetHostNames(f)

		if p.line != 0 {
			// TODO: line length?
			ew.write(dictSeparator, newline)
		}

		// this is a little crude, but will do for now. should probably find the
		// longest header and auto-format the keys
		ew.write("  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, f.GetTime()), newline)
		if p.opts.nodeName {
			ew.write("       NODE: ", f.GetNodeName(), newline)
		}
		ew.write(
			"     SOURCE: ", src, newline,
			"DESTINATION: ", dst, newline,
			"       TYPE: ", GetFlowType(f), newline,
			"    VERDICT: ", p.getVerdict(f), newline,
			"    SUMMARY: ", f.GetSummary(), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out packet: %v", ew.err)
		}
	case CompactOutput:
		var node string
		src, dst := p.GetHostNames(f)
		srcIdentity, dstIdentity := p.GetSecurityIdentities(f)

		if p.opts.nodeName {
			node = fmt.Sprintf(" [%s]", f.GetNodeName())
		}
		arrow := "->"
		if f.GetIsReply() == nil {
			// direction is unknown.
			arrow = "<>"
		} else if f.GetIsReply().Value {
			// flip the arrow and src/dst for reply packets.
			src, dst = dst, src
			srcIdentity, dstIdentity = dstIdentity, srcIdentity
			arrow = "<-"
		}
		_, err := fmt.Fprintf(p.opts.w,
			"%s%s: %s %s %s %s %s %s %s (%s)\n",
			fmtTimestamp(p.opts.timeFormat, f.GetTime()),
			node,
			src,
			srcIdentity,
			arrow,
			dst,
			dstIdentity,
			GetFlowType(f),
			p.getVerdict(f),
			f.GetSummary())
		if err != nil {
			return fmt.Errorf("failed to write out packet: %v", err)
		}
	case JSONOutput:
		return p.jsonEncoder.Encode(f)
	case JSONPBOutput:
		return p.jsonEncoder.Encode(res)
	}
	p.line++
	return nil
}

// joinWithCutOff performs a strings.Join, but will omit elements if the
// resulting string is longer than targetLen. The resulting string may be
// longer than targetLen, as it will always print at least one element.
// The number of omitted elements is appended to the resulting string as
// " (and N more)".
func joinWithCutOff(elems []string, sep string, targetLen int) string {
	strLen := 0
	end := len(elems)
	for i, elem := range elems {
		strLen += len(elem) + len(sep)
		if strLen > targetLen && i > 0 {
			end = i
			break
		}
	}

	joined := strings.Join(elems[:end], sep)
	omitted := len(elems) - end
	if omitted == 0 {
		return joined
	}

	return fmt.Sprintf("%s (and %d more)", joined, omitted)
}

// WriteProtoNodeStatusEvent writes a node status event into the error stream
func (p *Printer) WriteProtoNodeStatusEvent(r *observerpb.GetFlowsResponse) error {
	s := r.GetNodeStatus()
	if s == nil {
		return errors.New("not a node status event")
	}

	if !p.opts.enableDebug {
		switch s.GetStateChange() {
		case relaypb.NodeState_NODE_ERROR, relaypb.NodeState_NODE_UNAVAILABLE:
			break
		default:
			// skips informal messages in non-debug mode
			return nil
		}
	}

	switch p.opts.output {
	case JSONOutput, JSONPBOutput:
		return json.NewEncoder(p.opts.werr).Encode(r)
	case DictOutput:
		// this is a bit crude, but in case stdout and stderr are interleaved,
		// we want to make sure the separators are still printed to clearly
		// separate flows from node events.
		if p.line != 0 {
			_, err := fmt.Fprintln(p.opts.w, dictSeparator)
			if err != nil {
				return err
			}
		} else {
			p.line++
		}
		nodeNames := joinWithCutOff(s.NodeNames, ", ", nodeNamesCutOff)
		message := "N/A"
		if m := s.GetMessage(); len(m) != 0 {
			message = strconv.Quote(m)
		}
		_, err := fmt.Fprint(p.opts.werr,
			"  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, r.GetTime()), newline,
			"      STATE: ", s.StateChange.String(), newline,
			"      NODES: ", nodeNames, newline,
			"    MESSAGE: ", message, newline,
		)
		if err != nil {
			return fmt.Errorf("failed to write out node status: %v", err)
		}
	case TabOutput, CompactOutput:
		numNodes := len(s.NodeNames)
		nodeNames := joinWithCutOff(s.NodeNames, ", ", nodeNamesCutOff)
		prefix := fmt.Sprintf("%s [%s]", fmtTimestamp(p.opts.timeFormat, r.GetTime()), r.GetNodeName())
		msg := fmt.Sprintf("%s: unknown node status event: %+v", prefix, s)
		switch s.StateChange {
		case relaypb.NodeState_NODE_CONNECTED:
			msg = fmt.Sprintf("%s: Receiving flows from %d nodes: %s", prefix, numNodes, nodeNames)
		case relaypb.NodeState_NODE_UNAVAILABLE:
			msg = fmt.Sprintf("%s: %d nodes are unavailable: %s", prefix, numNodes, nodeNames)
		case relaypb.NodeState_NODE_GONE:
			msg = fmt.Sprintf("%s: %d nodes removed from cluster: %s", prefix, numNodes, nodeNames)
		case relaypb.NodeState_NODE_ERROR:
			msg = fmt.Sprintf("%s: Error %q on %d nodes: %s", prefix, s.Message, numNodes, nodeNames)
		}

		return p.WriteErr(msg)
	}

	return nil
}

func formatServiceAddr(a *pb.ServiceUpsertNotificationAddr) string {
	return net.JoinHostPort(a.Ip, strconv.Itoa(int(a.Port)))
}

func getAgentEventDetails(e *pb.AgentEvent, timeLayout string) string {
	switch e.GetType() {
	case pb.AgentEventType_AGENT_EVENT_UNKNOWN:
		if u := e.GetUnknown(); u != nil {
			return fmt.Sprintf("type: %s, notification: %s", u.Type, u.Notification)
		}
	case pb.AgentEventType_AGENT_STARTED:
		if a := e.GetAgentStart(); a != nil {
			return fmt.Sprintf("start time: %s", fmtTimestamp(timeLayout, a.Time))
		}
	case pb.AgentEventType_POLICY_UPDATED, pb.AgentEventType_POLICY_DELETED:
		if p := e.GetPolicyUpdate(); p != nil {
			return fmt.Sprintf("labels: [%s], revision: %d, count: %d",
				strings.Join(p.Labels, ","), p.Revision, p.RuleCount)
		}
	case pb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS, pb.AgentEventType_ENDPOINT_REGENERATE_FAILURE:
		if r := e.GetEndpointRegenerate(); r != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "id: %d, labels: [%s]", r.Id, strings.Join(r.Labels, ","))
			if re := r.Error; re != "" {
				fmt.Fprintf(&sb, ", error: %s", re)
			}
			return sb.String()
		}
	case pb.AgentEventType_ENDPOINT_CREATED, pb.AgentEventType_ENDPOINT_DELETED:
		if ep := e.GetEndpointUpdate(); ep != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "id: %d", ep.Id)
			if n := ep.Namespace; n != "" {
				fmt.Fprintf(&sb, ", namespace: %s", n)
			}
			if n := ep.PodName; n != "" {
				fmt.Fprintf(&sb, ", pod name: %s", n)
			}
			return sb.String()
		}
	case pb.AgentEventType_IPCACHE_UPSERTED, pb.AgentEventType_IPCACHE_DELETED:
		if i := e.GetIpcacheUpdate(); i != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "cidr: %s, identity: %d", i.Cidr, i.Identity)
			if i.OldIdentity != nil {
				fmt.Fprintf(&sb, ", old identity: %d", i.OldIdentity.Value)
			}
			if i.HostIp != "" {
				fmt.Fprintf(&sb, ", host ip: %s", i.HostIp)
			}
			if i.OldHostIp != "" {
				fmt.Fprintf(&sb, ", old host ip: %s", i.OldHostIp)
			}
			fmt.Fprintf(&sb, ", encrypt key: %d", i.EncryptKey)
			return sb.String()
		}
	case pb.AgentEventType_SERVICE_UPSERTED:
		if svc := e.GetServiceUpsert(); svc != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "id: %d", svc.Id)
			if fe := svc.FrontendAddress; fe != nil {
				fmt.Fprintf(&sb, ", frontend: %s", formatServiceAddr(fe))
			}
			if bes := svc.BackendAddresses; len(bes) != 0 {
				backends := make([]string, 0, len(bes))
				for _, a := range bes {
					backends = append(backends, formatServiceAddr(a))
				}
				fmt.Fprintf(&sb, ", backends: [%s]", strings.Join(backends, ","))
			}
			if t := svc.Type; t != "" {
				fmt.Fprintf(&sb, ", type: %s", t)
			}
			if tp := svc.TrafficPolicy; tp != "" {
				fmt.Fprintf(&sb, ", traffic policy: %s", tp)
			}
			if ns := svc.Namespace; ns != "" {
				fmt.Fprintf(&sb, ", namespace: %s", ns)
			}
			if n := svc.Name; n != "" {
				fmt.Fprintf(&sb, ", name: %s", n)
			}
			return sb.String()
		}
	case pb.AgentEventType_SERVICE_DELETED:
		if s := e.GetServiceDelete(); s != nil {
			return fmt.Sprintf("id: %d", s.Id)
		}
	}
	return "UNKNOWN"
}

// WriteProtoAgentEvent writes v1.AgentEvent into the output writer.
func (p *Printer) WriteProtoAgentEvent(r *observerpb.GetAgentEventsResponse) error {
	e := r.GetAgentEvent()
	if e == nil {
		return errors.New("not an agent event")
	}

	switch p.opts.output {
	case JSONOutput:
		return p.jsonEncoder.Encode(e)
	case JSONPBOutput:
		return p.jsonEncoder.Encode(r)
	case DictOutput:
		ew := &errWriter{w: p.opts.w}

		if p.line != 0 {
			ew.write(dictSeparator)
		}

		ew.write("  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, r.GetTime()), newline)
		if p.opts.nodeName {
			ew.write("       NODE: ", r.GetNodeName(), newline)
		}
		ew.write(
			"       TYPE: ", e.GetType(), newline,
			"    DETAILS: ", getAgentEventDetails(e, p.opts.timeFormat), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out agent event: %v", ew.err)
		}
	case TabOutput:
		ew := &errWriter{w: p.tw}
		if p.line == 0 {
			ew.write("TIMESTAMP", tab)
			if p.opts.nodeName {
				ew.write("NODE", tab)
			}
			ew.write(
				"TYPE", tab,
				"DETAILS", newline,
			)
		}
		ew.write(fmtTimestamp(p.opts.timeFormat, r.GetTime()), tab)
		if p.opts.nodeName {
			ew.write(r.GetNodeName(), tab)
		}
		ew.write(
			e.GetType(), tab,
			getAgentEventDetails(e, p.opts.timeFormat), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out agent event: %v", ew.err)
		}
	case CompactOutput:
		var node string

		if p.opts.nodeName {
			node = fmt.Sprintf(" [%s]", r.GetNodeName())
		}
		_, err := fmt.Fprintf(p.opts.w,
			"%s%s: %s (%s)\n",
			fmtTimestamp(p.opts.timeFormat, r.GetTime()),
			node,
			e.GetType(),
			getAgentEventDetails(e, p.opts.timeFormat))
		if err != nil {
			return fmt.Errorf("failed to write out agent event: %v", err)
		}
	}
	p.line++
	return nil
}

func fmtHexUint32(v *wrapperspb.UInt32Value) string {
	if v == nil {
		return "N/A"
	}
	return "0x" + strconv.FormatUint(uint64(v.GetValue()), 16)
}

func fmtCPU(cpu *wrapperspb.Int32Value) string {
	if cpu == nil {
		return "N/A"
	}
	return fmt.Sprintf("%02d", cpu.GetValue())
}

func fmtEndpointShort(ep *pb.Endpoint) string {
	if ep == nil {
		return "N/A"
	}

	str := fmt.Sprintf("ID: %d", ep.GetID())
	if ns, pod := ep.GetNamespace(), ep.GetPodName(); ns != "" && pod != "" {
		str = fmt.Sprintf("%s/%s (%s)", ns, pod, str)
	} else if lbls := ep.GetLabels(); len(lbls) == 1 && strings.HasPrefix("reserved:", lbls[0]) {
		str = fmt.Sprintf("%s (%s)", lbls[0], str)
	}

	return str
}

// WriteProtoDebugEvent writes a flowpb.DebugEvent into the output writer.
func (p *Printer) WriteProtoDebugEvent(r *observerpb.GetDebugEventsResponse) error {
	e := r.GetDebugEvent()
	if e == nil {
		return errors.New("not a debug event")
	}

	switch p.opts.output {
	case JSONOutput:
		return p.jsonEncoder.Encode(e)
	case JSONPBOutput:
		return p.jsonEncoder.Encode(r)
	case DictOutput:
		ew := &errWriter{w: p.opts.w}

		if p.line != 0 {
			ew.write(dictSeparator)
		}

		ew.write("  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, r.GetTime()), newline)
		if p.opts.nodeName {
			ew.write("       NODE: ", r.GetNodeName(), newline)
		}
		ew.write(
			"",
			"       TYPE: ", e.GetType(), newline,
			"       FROM: ", fmtEndpointShort(e.GetSource()), newline,
			"       MARK: ", fmtHexUint32(e.GetHash()), newline,
			"        CPU: ", fmtCPU(e.GetCpu()), newline,
			"    MESSAGE: ", e.GetMessage(), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out debug event: %v", ew.err)
		}
	case TabOutput:
		ew := &errWriter{w: p.tw}
		if p.line == 0 {
			ew.write("TIMESTAMP", tab)
			if p.opts.nodeName {
				ew.write("NODE", tab)
			}
			ew.write(
				"FROM", tab, tab,
				"TYPE", tab,
				"CPU/MARK", tab,
				"MESSAGE", newline,
			)
		}
		ew.write(fmtTimestamp(p.opts.timeFormat, r.GetTime()), tab)
		if p.opts.nodeName {
			ew.write(r.GetNodeName(), tab)
		}
		ew.write(
			fmtEndpointShort(e.GetSource()), tab, tab,
			e.GetType(), tab,
			fmtCPU(e.GetCpu()), space, fmtHexUint32(e.GetHash()), tab,
			e.GetMessage(), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out debug event: %v", ew.err)
		}
	case CompactOutput:
		var node string
		if p.opts.nodeName {
			node = fmt.Sprintf(" [%s]", r.GetNodeName())
		}
		_, err := fmt.Fprintf(p.opts.w,
			"%s%s: %s %s MARK: %s CPU: %s (%s)\n",
			fmtTimestamp(p.opts.timeFormat, r.GetTime()),
			node,
			fmtEndpointShort(e.GetSource()),
			e.GetType(),
			fmtHexUint32(e.GetHash()),
			fmtCPU(e.GetCpu()),
			e.GetMessage(),
		)
		if err != nil {
			return fmt.Errorf("failed to write out debug event: %v", err)
		}
	}
	p.line++
	return nil
}

// Hostname returns a "host:ip" formatted pair for the given ip and port. If
// port is empty, only the host is returned. The host part is either the pod or
// service name (if set), or a comma-separated list of domain names (if set),
// or just the ip address if EnableIPTranslation is false and/or there are no
// pod nor service name and domain names.
func (p *Printer) Hostname(ip, port string, ns, pod, svc string, names []string) (host string) {
	host = ip
	if p.opts.enableIPTranslation {
		if pod != "" {
			// path.Join omits the slash if ns is empty
			host = path.Join(ns, pod)
		} else if svc != "" {
			host = path.Join(ns, svc)
		} else if len(names) != 0 {
			host = strings.Join(names, ",")
		}
	}

	if port != "" && port != "0" {
		return net.JoinHostPort(host, p.color.port(port))
	}

	return host
}

// WriteGetFlowsResponse prints GetFlowsResponse according to the printer configuration.
func (p *Printer) WriteGetFlowsResponse(res *observerpb.GetFlowsResponse) error {
	switch r := res.GetResponseTypes().(type) {
	case *observerpb.GetFlowsResponse_Flow:
		return p.WriteProtoFlow(res)
	case *observerpb.GetFlowsResponse_NodeStatus:
		return p.WriteProtoNodeStatusEvent(res)
	case nil:
		return nil
	default:
		if p.opts.enableDebug {
			msg := fmt.Sprintf("unknown response type: %+v", r)
			return p.WriteErr(msg)
		}
		return nil
	}
}

// WriteServerStatusResponse writes server status response into the output
// writer.
func (p *Printer) WriteServerStatusResponse(res *observerpb.ServerStatusResponse) error {
	if res == nil {
		return nil
	}

	numConnectedNodes := "N/A"
	if n := res.GetNumConnectedNodes(); n != nil {
		numConnectedNodes = fmt.Sprintf("%d", n.Value)
	}
	numUnavailableNodes := "N/A"
	if n := res.GetNumUnavailableNodes(); n != nil {
		numUnavailableNodes = fmt.Sprintf("%d", n.Value)
	}

	switch p.opts.output {
	case TabOutput:
		ew := &errWriter{w: p.tw}
		ew.write(
			"NUM FLOWS", tab,
			"MAX FLOWS", tab,
			"SEEN FLOWS", tab,
			"UPTIME", tab,
			"NUM CONNECTED NODES", tab,
			"NUM UNAVAILABLE NODES", tab,
			"VERSION", newline,
			uint64Grouping(res.GetNumFlows()), tab,
			uint64Grouping(res.GetMaxFlows()), tab,
			uint64Grouping(res.GetSeenFlows()), tab,
			formatDurationNS(res.GetUptimeNs()), tab,
			numConnectedNodes, tab,
			numUnavailableNodes, tab,
			res.GetVersion(), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out server status: %v", ew.err)
		}
	case DictOutput:
		ew := &errWriter{w: p.opts.w}
		ew.write(
			"          NUM FLOWS: ", uint64Grouping(res.GetNumFlows()), newline,
			"          MAX FLOWS: ", uint64Grouping(res.GetMaxFlows()), newline,
			"         SEEN FLOWS: ", uint64Grouping(res.GetSeenFlows()), newline,
			"             UPTIME: ", formatDurationNS(res.GetUptimeNs()), newline,
			"NUM CONNECTED NODES: ", numConnectedNodes, newline,
			" NUM UNAVAIL. NODES: ", numUnavailableNodes, newline,
			"            VERSION: ", res.GetVersion(), newline,
		)
		if ew.err != nil {
			return fmt.Errorf("failed to write out server status: %v", ew.err)
		}
	case CompactOutput:
		ew := &errWriter{w: p.opts.w}
		flowsRatio := ""
		if res.MaxFlows > 0 {
			flowsRatio = fmt.Sprintf(" (%.2f%%)", (float64(res.NumFlows)/float64(res.MaxFlows))*100)
		}
		ew.writef("Current/Max Flows: %v/%v%s\n", uint64Grouping(res.NumFlows), uint64Grouping(res.MaxFlows), flowsRatio)

		flowsPerSec := "N/A"
		if uptime := time.Duration(res.UptimeNs).Seconds(); uptime > 0 {
			flowsPerSec = fmt.Sprintf("%.2f", float64(res.SeenFlows)/uptime)
		}
		ew.writef("Flows/s: %s\n", flowsPerSec)

		numConnected := res.GetNumConnectedNodes()
		numUnavailable := res.GetNumUnavailableNodes()
		if numConnected != nil {
			total := ""
			if numUnavailable != nil {
				total = fmt.Sprintf("/%d", numUnavailable.Value+numConnected.Value)
			}
			ew.writef("Connected Nodes: %d%s\n", numConnected.Value, total)
		}
		if numUnavailable != nil && numUnavailable.Value > 0 {
			if unavailable := res.GetUnavailableNodes(); unavailable != nil {
				sort.Strings(unavailable) // it's nicer when displaying unavailable nodes list
				if numUnavailable.Value > uint32(len(unavailable)) {
					unavailable = append(unavailable, fmt.Sprintf("and %d more...", numUnavailable.Value-uint32(len(unavailable))))
				}
				ew.writef("Unavailable Nodes: %d\n  - %s\n",
					numUnavailable.Value,
					strings.Join(unavailable, "\n  - "),
				)
			} else {
				ew.writef("Unavailable Nodes: %d\n", numUnavailable.Value)
			}
		}
		if ew.err != nil {
			return fmt.Errorf("failed to write out server status: %v", ew.err)
		}
	case JSONOutput, JSONPBOutput:
		return p.jsonEncoder.Encode(res)
	}
	return nil
}
