// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/time"
)

const (
	tab     = "\t"
	newline = "\n"
	space   = " "

	dictSeparator = "------------"

	nodeNamesCutOff = 50
)

// Printer for flows.
type Printer struct {
	opts          Options
	line          int
	tw            *tabwriter.Writer
	jsonEncoder   *json.Encoder
	color         *colorer
	writerBuilder *terminalEscaperBuilder
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
	case JSONLegacyOutput, JSONPBOutput:
		p.jsonEncoder = json.NewEncoder(p.opts.w)
	}

	p.writerBuilder = newTerminalEscaperBuilder(p.color.sequences())

	return p
}

// Close any outstanding operations going on in the printer.
func (p *Printer) Close() error {
	if p.tw != nil {
		return p.tw.Flush()
	}

	return nil
}

// GetPorts returns source and destination port of a flow.
func (p *Printer) GetPorts(f *flowpb.Flow) (string, string) {
	l4 := f.GetL4()
	if l4 == nil {
		return "", ""
	}
	switch l4.GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		return strconv.Itoa(int(l4.GetTCP().GetSourcePort())), strconv.Itoa(int(l4.GetTCP().GetDestinationPort()))
	case *flowpb.Layer4_UDP:
		return strconv.Itoa(int(l4.GetUDP().GetSourcePort())), strconv.Itoa(int(l4.GetUDP().GetDestinationPort()))
	case *flowpb.Layer4_SCTP:
		return strconv.Itoa(int(l4.GetSCTP().GetSourcePort())), strconv.Itoa(int(l4.GetSCTP().GetDestinationPort()))
	default:
		return "", ""
	}
}

// GetHostNames returns source and destination hostnames of a flow.
func (p *Printer) GetHostNames(f *flowpb.Flow) (string, string) {
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
		srcNamespace = src.GetNamespace()
		srcPodName = src.GetPodName()
	}
	if dst := f.GetDestination(); dst != nil {
		dstNamespace = dst.GetNamespace()
		dstPodName = dst.GetPodName()
	}
	if svc := f.GetSourceService(); svc != nil {
		srcNamespace = svc.GetNamespace()
		srcSvcName = svc.GetName()
	}
	if svc := f.GetDestinationService(); svc != nil {
		dstNamespace = svc.GetNamespace()
		dstSvcName = svc.GetName()
	}
	srcPort, dstPort := p.GetPorts(f)
	src := p.Hostname(f.GetIP().GetSource(), srcPort, srcNamespace, srcPodName, srcSvcName, f.GetSourceNames())
	dst := p.Hostname(f.GetIP().GetDestination(), dstPort, dstNamespace, dstPodName, dstSvcName, f.GetDestinationNames())
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
func (p *Printer) GetSecurityIdentities(f *flowpb.Flow) (srcIdentity, dstIdentity string) {
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
func GetFlowType(f *flowpb.Flow) string {
	if l7 := f.GetL7(); l7 != nil {
		l7Protocol := "l7"
		l7Type := strings.ToLower(l7.GetType().String())
		switch l7.GetRecord().(type) {
		case *flowpb.Layer7_Http:
			l7Protocol = "http"
		case *flowpb.Layer7_Dns:
			l7Protocol = "dns"
			l7Type += " " + l7.GetDns().GetObservationSource()
		case *flowpb.Layer7_Kafka:
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
		return fmt.Sprintf("%s:%s %s",
			api.MessageTypeNamePolicyVerdict,
			api.PolicyMatchType(f.GetPolicyMatchType()).String(),
			f.GetTrafficDirection().String())

	case api.MessageTypeCapture:
		return f.GetDebugCapturePoint().String()
	case api.MessageTypeTraceSock:
		switch f.GetSockXlatePoint() {
		case flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_FWD:
			return "post-xlate-fwd"
		case flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_POST_DIRECTION_REV:
			return "post-xlate-rev"
		case flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_PRE_DIRECTION_FWD:
			return "pre-xlate-fwd"
		case flowpb.SocketTranslationPoint_SOCK_XLATE_POINT_PRE_DIRECTION_REV:
			return "pre-xlate-rev"
		}
		return f.GetSockXlatePoint().String()
	}

	return "UNKNOWN"
}

func (p Printer) getVerdict(f *flowpb.Flow) string {
	verdict := f.GetVerdict()
	msg := verdict.String()
	switch verdict {
	case flowpb.Verdict_FORWARDED, flowpb.Verdict_REDIRECTED:
		if f.GetEventType().GetType() == api.MessageTypePolicyVerdict {
			msg = "ALLOWED"
		}
		return p.color.verdictForwarded(msg)
	case flowpb.Verdict_DROPPED, flowpb.Verdict_ERROR:
		if f.GetEventType().GetType() == api.MessageTypePolicyVerdict {
			msg = "DENIED"
		}
		return p.color.verdictDropped(msg)
	case flowpb.Verdict_AUDIT:
		if f.GetEventType().GetType() == api.MessageTypePolicyVerdict {
			msg = "AUDITED"
		}
		return p.color.verdictAudit(msg)
	case flowpb.Verdict_TRACED:
		return p.color.verdictTraced(msg)
	case flowpb.Verdict_TRANSLATED:
		return p.color.verdictTranslated(msg)
	default:
		return msg
	}
}

func (p Printer) getSummary(f *flowpb.Flow) string {
	auth := p.getAuth(f)
	if auth == "" {
		return f.GetSummary()
	}

	return fmt.Sprintf("%s; Auth: %s", f.GetSummary(), auth)
}

func (p Printer) getAuth(f *flowpb.Flow) string {
	auth := f.GetAuthType()
	msg := auth.String()
	switch auth {
	case flowpb.AuthType_DISABLED:
		// if auth is disabled we do not want to display anything
		return ""
	case flowpb.AuthType_TEST_ALWAYS_FAIL:
		return p.color.authTestAlwaysFail(msg)
	default:
		return p.color.authIsEnabled(msg)
	}
}

// WriteProtoFlow writes v1.Flow into the output writer.
func (p *Printer) WriteProtoFlow(res *observerpb.GetFlowsResponse) error {
	f := res.GetFlow()

	switch p.opts.output {
	case TabOutput:
		w := p.createTabWriter()
		src, dst := p.GetHostNames(f)

		if p.line == 0 {
			w.print("TIMESTAMP", tab)
			if p.opts.nodeName {
				w.print("NODE", tab)
			}
			w.print(
				"SOURCE", tab,
				"DESTINATION", tab,
				"TYPE", tab,
				"VERDICT", tab,
				"SUMMARY", newline,
			)
		}
		w.print(fmtTimestamp(p.opts.timeFormat, f.GetTime()), tab)
		if p.opts.nodeName {
			w.print(f.GetNodeName(), tab)
		}
		w.print(
			src, tab,
			dst, tab,
			GetFlowType(f), tab,
			p.getVerdict(f), tab,
			p.getSummary(f), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out packet: %w", w.err)
		}
	case DictOutput:
		w := p.createStdoutWriter()
		src, dst := p.GetHostNames(f)

		if p.line != 0 {
			// TODO: line length?
			w.print(dictSeparator, newline)
		}

		// this is a little crude, but will do for now. should probably find the
		// longest header and auto-format the keys
		w.print("  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, f.GetTime()), newline)
		if p.opts.nodeName {
			w.print("       NODE: ", f.GetNodeName(), newline)
		}
		w.print(
			"     SOURCE: ", src, newline,
			"DESTINATION: ", dst, newline,
			"       TYPE: ", GetFlowType(f), newline,
			"    VERDICT: ", p.getVerdict(f), newline,
			"    SUMMARY: ", p.getSummary(f), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out packet: %w", w.err)
		}
	case CompactOutput:
		w := p.createStdoutWriter()
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
		} else if f.GetIsReply().GetValue() {
			// flip the arrow and src/dst for reply packets.
			src, dst = dst, src
			srcIdentity, dstIdentity = dstIdentity, srcIdentity
			arrow = "<-"
		}
		w.printf(
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
			p.getSummary(f))
		if w.err != nil {
			return fmt.Errorf("failed to write out packet: %w", w.err)
		}
	case JSONLegacyOutput:
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

// WriteProtoNodeStatusEvent writes a node status event into the error stream.
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
	case JSONPBOutput:
		return json.NewEncoder(p.opts.werr).Encode(r)
	case DictOutput:
		w := p.createStderrWriter()
		// this is a bit crude, but in case stdout and stderr are interleaved,
		// we want to make sure the separators are still printed to clearly
		// separate flows from node events.
		if p.line != 0 {
			w.print(dictSeparator + "\n")
		} else {
			p.line++
		}
		nodeNames := joinWithCutOff(s.GetNodeNames(), ", ", nodeNamesCutOff)
		message := "N/A"
		if m := s.GetMessage(); len(m) != 0 {
			message = strconv.Quote(m)
		}
		w.print(
			"  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, r.GetTime()), newline,
			"      STATE: ", s.GetStateChange().String(), newline,
			"      NODES: ", nodeNames, newline,
			"    MESSAGE: ", message, newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out node status: %w", w.err)
		}
	case TabOutput, CompactOutput:
		w := p.createStderrWriter()
		numNodes := len(s.GetNodeNames())
		nodeNames := joinWithCutOff(s.GetNodeNames(), ", ", nodeNamesCutOff)
		prefix := fmt.Sprintf("%s [%s]", fmtTimestamp(p.opts.timeFormat, r.GetTime()), r.GetNodeName())
		msg := fmt.Sprintf("%s: unknown node status event: %+v", prefix, s)
		switch s.GetStateChange() {
		case relaypb.NodeState_NODE_CONNECTED:
			msg = fmt.Sprintf("%s: Receiving flows from %d nodes: %s", prefix, numNodes, nodeNames)
		case relaypb.NodeState_NODE_UNAVAILABLE:
			msg = fmt.Sprintf("%s: %d nodes are unavailable: %s", prefix, numNodes, nodeNames)
		case relaypb.NodeState_NODE_GONE:
			msg = fmt.Sprintf("%s: %d nodes removed from cluster: %s", prefix, numNodes, nodeNames)
		case relaypb.NodeState_NODE_ERROR:
			msg = fmt.Sprintf("%s: Error %q on %d nodes: %s", prefix, s.GetMessage(), numNodes, nodeNames)
		}
		w.print(msg + "\n")
		if w.err != nil {
			return fmt.Errorf("failed to write out node status: %w", w.err)
		}
	}

	return nil
}

func formatServiceAddr(a *flowpb.ServiceUpsertNotificationAddr) string {
	return net.JoinHostPort(a.GetIp(), strconv.Itoa(int(a.GetPort())))
}

func getAgentEventDetails(e *flowpb.AgentEvent, timeLayout string) string {
	switch e.GetType() {
	case flowpb.AgentEventType_AGENT_EVENT_UNKNOWN:
		if u := e.GetUnknown(); u != nil {
			return fmt.Sprintf("type: %s, notification: %s", u.GetType(), u.GetNotification())
		}
	case flowpb.AgentEventType_AGENT_STARTED:
		if a := e.GetAgentStart(); a != nil {
			return fmt.Sprintf("start time: %s", fmtTimestamp(timeLayout, a.GetTime()))
		}
	case flowpb.AgentEventType_POLICY_UPDATED, flowpb.AgentEventType_POLICY_DELETED:
		if p := e.GetPolicyUpdate(); p != nil {
			return fmt.Sprintf("labels: [%s], revision: %d, count: %d",
				strings.Join(p.GetLabels(), ","), p.GetRevision(), p.GetRuleCount())
		}
	case flowpb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS, flowpb.AgentEventType_ENDPOINT_REGENERATE_FAILURE:
		if r := e.GetEndpointRegenerate(); r != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "id: %d, labels: [%s]", r.GetId(), strings.Join(r.GetLabels(), ","))
			if re := r.GetError(); re != "" {
				fmt.Fprintf(&sb, ", error: %s", re)
			}
			return sb.String()
		}
	case flowpb.AgentEventType_ENDPOINT_CREATED, flowpb.AgentEventType_ENDPOINT_DELETED:
		if ep := e.GetEndpointUpdate(); ep != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "id: %d", ep.GetId())
			if n := ep.GetNamespace(); n != "" {
				fmt.Fprintf(&sb, ", namespace: %s", n)
			}
			if n := ep.GetPodName(); n != "" {
				fmt.Fprintf(&sb, ", pod name: %s", n)
			}
			return sb.String()
		}
	case flowpb.AgentEventType_IPCACHE_UPSERTED, flowpb.AgentEventType_IPCACHE_DELETED:
		if i := e.GetIpcacheUpdate(); i != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "cidr: %s, identity: %d", i.GetCidr(), i.GetIdentity())
			if i.GetOldIdentity() != nil {
				fmt.Fprintf(&sb, ", old identity: %d", i.GetOldIdentity().GetValue())
			}
			if i.GetHostIp() != "" {
				fmt.Fprintf(&sb, ", host ip: %s", i.GetHostIp())
			}
			if i.GetOldHostIp() != "" {
				fmt.Fprintf(&sb, ", old host ip: %s", i.GetOldHostIp())
			}
			fmt.Fprintf(&sb, ", encrypt key: %d", i.GetEncryptKey())
			return sb.String()
		}
	case flowpb.AgentEventType_SERVICE_UPSERTED:
		if svc := e.GetServiceUpsert(); svc != nil {
			var sb strings.Builder
			fmt.Fprintf(&sb, "id: %d", svc.GetId())
			if fe := svc.GetFrontendAddress(); fe != nil {
				fmt.Fprintf(&sb, ", frontend: %s", formatServiceAddr(fe))
			}
			if bes := svc.GetBackendAddresses(); len(bes) != 0 {
				backends := make([]string, 0, len(bes))
				for _, a := range bes {
					backends = append(backends, formatServiceAddr(a))
				}
				fmt.Fprintf(&sb, ", backends: [%s]", strings.Join(backends, ","))
			}
			if t := svc.GetType(); t != "" {
				fmt.Fprintf(&sb, ", type: %s", t)
			}
			if tp := svc.GetTrafficPolicy(); tp != "" {
				fmt.Fprintf(&sb, ", traffic policy: %s", tp)
			}
			if ns := svc.GetNamespace(); ns != "" {
				fmt.Fprintf(&sb, ", namespace: %s", ns)
			}
			if n := svc.GetName(); n != "" {
				fmt.Fprintf(&sb, ", name: %s", n)
			}
			return sb.String()
		}
	case flowpb.AgentEventType_SERVICE_DELETED:
		if s := e.GetServiceDelete(); s != nil {
			return fmt.Sprintf("id: %d", s.GetId())
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
	case JSONLegacyOutput:
		return p.jsonEncoder.Encode(e)
	case JSONPBOutput:
		return p.jsonEncoder.Encode(r)
	case DictOutput:
		w := p.createStdoutWriter()

		if p.line != 0 {
			w.print(dictSeparator)
		}

		w.print("  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, r.GetTime()), newline)
		if p.opts.nodeName {
			w.print("       NODE: ", r.GetNodeName(), newline)
		}
		w.print(
			"       TYPE: ", e.GetType(), newline,
			"    DETAILS: ", getAgentEventDetails(e, p.opts.timeFormat), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out agent event: %w", w.err)
		}
	case TabOutput:
		w := p.createTabWriter()
		if p.line == 0 {
			w.print("TIMESTAMP", tab)
			if p.opts.nodeName {
				w.print("NODE", tab)
			}
			w.print(
				"TYPE", tab,
				"DETAILS", newline,
			)
		}
		w.print(fmtTimestamp(p.opts.timeFormat, r.GetTime()), tab)
		if p.opts.nodeName {
			w.print(r.GetNodeName(), tab)
		}
		w.print(
			e.GetType(), tab,
			getAgentEventDetails(e, p.opts.timeFormat), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out agent event: %w", w.err)
		}
	case CompactOutput:
		w := p.createStdoutWriter()
		var node string

		if p.opts.nodeName {
			node = fmt.Sprintf(" [%s]", r.GetNodeName())
		}
		w.printf("%s%s: %s (%s)\n",
			fmtTimestamp(p.opts.timeFormat, r.GetTime()),
			node,
			e.GetType(),
			getAgentEventDetails(e, p.opts.timeFormat),
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out agent event: %w", w.err)
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

func fmtEndpointShort(ep *flowpb.Endpoint) string {
	if ep == nil {
		return "N/A"
	}

	str := fmt.Sprintf("ID: %d", ep.GetID())
	if ns, pod := ep.GetNamespace(), ep.GetPodName(); ns != "" && pod != "" {
		str = fmt.Sprintf("%s/%s (%s)", ns, pod, str)
	} else if lbls := ep.GetLabels(); len(lbls) == 1 && strings.HasPrefix(lbls[0], "reserved:") {
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
	case JSONLegacyOutput:
		return p.jsonEncoder.Encode(e)
	case JSONPBOutput:
		return p.jsonEncoder.Encode(r)
	case DictOutput:
		w := p.createStdoutWriter()

		if p.line != 0 {
			w.print(dictSeparator)
		}

		w.print("  TIMESTAMP: ", fmtTimestamp(p.opts.timeFormat, r.GetTime()), newline)
		if p.opts.nodeName {
			w.print("       NODE: ", r.GetNodeName(), newline)
		}
		w.print(
			"",
			"       TYPE: ", e.GetType(), newline,
			"       FROM: ", fmtEndpointShort(e.GetSource()), newline,
			"       MARK: ", fmtHexUint32(e.GetHash()), newline,
			"        CPU: ", fmtCPU(e.GetCpu()), newline,
			"    MESSAGE: ", e.GetMessage(), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out debug event: %w", w.err)
		}
	case TabOutput:
		w := p.createTabWriter()
		if p.line == 0 {
			w.print("TIMESTAMP", tab)
			if p.opts.nodeName {
				w.print("NODE", tab)
			}
			w.print(
				"FROM", tab, tab,
				"TYPE", tab,
				"CPU/MARK", tab,
				"MESSAGE", newline,
			)
		}
		w.print(fmtTimestamp(p.opts.timeFormat, r.GetTime()), tab)
		if p.opts.nodeName {
			w.print(r.GetNodeName(), tab)
		}
		w.print(
			fmtEndpointShort(e.GetSource()), tab, tab,
			e.GetType(), tab,
			fmtCPU(e.GetCpu()), space, fmtHexUint32(e.GetHash()), tab,
			e.GetMessage(), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out debug event: %w", w.err)
		}
	case CompactOutput:
		w := p.createStdoutWriter()
		var node string
		if p.opts.nodeName {
			node = fmt.Sprintf(" [%s]", r.GetNodeName())
		}
		w.printf("%s%s: %s %s MARK: %s CPU: %s (%s)\n",
			fmtTimestamp(p.opts.timeFormat, r.GetTime()),
			node,
			fmtEndpointShort(e.GetSource()),
			e.GetType(),
			fmtHexUint32(e.GetHash()),
			fmtCPU(e.GetCpu()),
			e.GetMessage(),
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out debug event: %w", w.err)
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
		switch {
		case pod != "":
			// path.Join omits the slash if ns is empty
			host = path.Join(ns, pod)
		case svc != "":
			host = path.Join(ns, svc)
		case len(names) != 0:
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
	case *observerpb.GetFlowsResponse_LostEvents:
		return p.WriteLostEvent(res)
	case nil:
		return nil
	default:
		if p.opts.enableDebug {
			w := p.createStderrWriter()
			msg := fmt.Sprintf("unknown response type: %+v", r)
			w.print(msg + "\n")
			if w.err != nil {
				return fmt.Errorf("failed to write out flow response: %w", w.err)
			}
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
		numConnectedNodes = fmt.Sprintf("%d", n.GetValue())
	}
	numUnavailableNodes := "N/A"
	if n := res.GetNumUnavailableNodes(); n != nil {
		numUnavailableNodes = fmt.Sprintf("%d", n.GetValue())
	}
	flowsPerSec := "N/A"
	if fr := res.GetFlowsRate(); fr > 0 {
		flowsPerSec = fmt.Sprintf("%.2f", fr)
	}

	switch p.opts.output {
	case TabOutput:
		w := p.createTabWriter()
		w.print(
			"NUM FLOWS", tab,
			"MAX FLOWS", tab,
			"SEEN FLOWS", tab,
			"FLOWS PER SECOND", tab,
			"UPTIME", tab,
			"NUM CONNECTED NODES", tab,
			"NUM UNAVAILABLE NODES", tab,
			"VERSION", newline,
			uint64Grouping(res.GetNumFlows()), tab,
			uint64Grouping(res.GetMaxFlows()), tab,
			uint64Grouping(res.GetSeenFlows()), tab,
			flowsPerSec, tab,
			formatDurationNS(res.GetUptimeNs()), tab,
			numConnectedNodes, tab,
			numUnavailableNodes, tab,
			res.GetVersion(), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out server status: %w", w.err)
		}
	case DictOutput:
		w := p.createStdoutWriter()
		w.print(
			"          NUM FLOWS: ", uint64Grouping(res.GetNumFlows()), newline,
			"          MAX FLOWS: ", uint64Grouping(res.GetMaxFlows()), newline,
			"         SEEN FLOWS: ", uint64Grouping(res.GetSeenFlows()), newline,
			"   FLOWS PER SECOND: ", flowsPerSec, newline,
			"             UPTIME: ", formatDurationNS(res.GetUptimeNs()), newline,
			"NUM CONNECTED NODES: ", numConnectedNodes, newline,
			" NUM UNAVAIL. NODES: ", numUnavailableNodes, newline,
			"            VERSION: ", res.GetVersion(), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out server status: %w", w.err)
		}
	case CompactOutput:
		w := p.createStdoutWriter()
		flowsRatio := ""
		if res.GetMaxFlows() > 0 {
			flowsRatio = fmt.Sprintf(" (%.2f%%)", (float64(res.GetNumFlows())/float64(res.GetMaxFlows()))*100)
		}
		w.printf("Current/Max Flows: %v/%v%s\n", uint64Grouping(res.GetNumFlows()), uint64Grouping(res.GetMaxFlows()), flowsRatio)

		if uptime := time.Duration(res.GetUptimeNs()).Seconds(); flowsPerSec == "N/A" && uptime > 0 {
			flowsPerSec = fmt.Sprintf("%.2f", float64(res.GetSeenFlows())/uptime)
		}
		w.printf("Flows/s: %s\n", flowsPerSec)

		numConnected := res.GetNumConnectedNodes()
		numUnavailable := res.GetNumUnavailableNodes()
		if numConnected != nil {
			total := ""
			if numUnavailable != nil {
				total = fmt.Sprintf("/%d", numUnavailable.GetValue()+numConnected.GetValue())
			}
			w.printf("Connected Nodes: %d%s\n", numConnected.GetValue(), total)
		}
		if numUnavailable != nil && numUnavailable.GetValue() > 0 {
			if unavailable := res.GetUnavailableNodes(); unavailable != nil {
				sort.Strings(unavailable) // it's nicer when displaying unavailable nodes list
				if numUnavailable.GetValue() > uint32(len(unavailable)) {
					unavailable = append(unavailable, fmt.Sprintf("and %d more...", numUnavailable.GetValue()-uint32(len(unavailable))))
				}
				w.printf("Unavailable Nodes: %d\n  - %s\n",
					numUnavailable.GetValue(),
					strings.Join(unavailable, "\n  - "),
				)
			} else {
				w.printf("Unavailable Nodes: %d\n", numUnavailable.GetValue())
			}
		}
		if w.err != nil {
			return fmt.Errorf("failed to write out server status: %w", w.err)
		}
	case JSONPBOutput:
		return p.jsonEncoder.Encode(res)
	}
	return nil
}

// WriteLostEvent writes v1.Flow into the output writer.
func (p *Printer) WriteLostEvent(res *observerpb.GetFlowsResponse) error {
	f := res.GetLostEvents()

	switch p.opts.output {
	case TabOutput:
		w := p.createTabWriter()
		src := f.GetSource()
		numEventsLost := f.GetNumEventsLost()
		cpu := f.GetCpu()

		if p.line == 0 {
			w.print("TIMESTAMP", tab)
			if p.opts.nodeName {
				w.print("NODE", tab)
			}
			w.print(
				"SOURCE", tab,
				"DESTINATION", tab,
				"TYPE", tab,
				"VERDICT", tab,
				"SUMMARY", newline,
			)
		}
		w.print("", tab)
		if p.opts.nodeName {
			w.print("", tab)
		}
		w.print(
			src, tab,
			"", tab,
			"EVENTS LOST", tab,
			"", tab,
			fmt.Sprintf("CPU(%d) - %d", cpu.GetValue(), numEventsLost), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out packet: %w", w.err)
		}
	case DictOutput:
		w := p.createStdoutWriter()
		src := f.GetSource()
		numEventsLost := f.GetNumEventsLost()
		cpu := f.GetCpu()
		if p.line != 0 {
			// TODO: line length?
			w.print(dictSeparator, newline)
		}

		// this is a little crude, but will do for now. should probably find the
		// longest header and auto-format the keys
		w.print("  TIMESTAMP: ", "", newline)
		if p.opts.nodeName {
			w.print("       NODE: ", "", newline)
		}
		w.print(
			"     SOURCE: ", src, newline,
			"       TYPE: ", "EVENTS LOST", newline,
			"    VERDICT: ", "", newline,
			"    SUMMARY: ", fmt.Sprintf("CPU(%d) - %d", cpu.GetValue(), numEventsLost), newline,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out packet: %w", w.err)
		}
	case CompactOutput:
		w := p.createStdoutWriter()
		src := f.GetSource()
		numEventsLost := f.GetNumEventsLost()
		cpu := f.GetCpu()

		w.printf("EVENTS LOST: %s CPU(%d) %d\n",
			src,
			cpu.GetValue(),
			numEventsLost,
		)
		if w.err != nil {
			return fmt.Errorf("failed to write out packet: %w", w.err)
		}
	case JSONLegacyOutput:
		return p.jsonEncoder.Encode(f)
	case JSONPBOutput:
		return p.jsonEncoder.Encode(res)
	}
	p.line++
	return nil
}

func (p *Printer) createStdoutWriter() *terminalEscaperWriter {
	return p.writerBuilder.NewWriter(p.opts.w)
}

func (p *Printer) createStderrWriter() *terminalEscaperWriter {
	return p.writerBuilder.NewWriter(p.opts.werr)
}

func (p *Printer) createTabWriter() *terminalEscaperWriter {
	return p.writerBuilder.NewWriter(p.tw)
}
