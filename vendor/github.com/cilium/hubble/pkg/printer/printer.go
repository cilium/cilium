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

package printer

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
	pb "github.com/cilium/hubble/api/v1/flow"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/gogo/protobuf/types"
	"github.com/google/gopacket/layers"
)

// additional named ports that are related to hubble and cilium, which do
// not appear in the "well known" list of Golang ports... yet.
var namedPorts = map[int]string{
	4240: "cilium-health",
}

// Printer for flows.
type Printer struct {
	opts        Options
	line        int
	tw          *tabwriter.Writer
	jsonEncoder *json.Encoder
}

// New Printer.
func New(fopts ...Option) *Printer {
	// default options
	opts := Options{
		output: TabOutput,
		w:      os.Stdout,
		werr:   os.Stderr,
	}

	// apply optional parameters
	for _, fopt := range fopts {
		fopt(&opts)
	}

	p := &Printer{
		opts: opts,
	}

	switch opts.output {
	case TabOutput:
		// initialize tabwriter since it's going to be needed
		p.tw = tabwriter.NewWriter(opts.w, 2, 0, 3, ' ', 0)
	case JSONOutput:
		p.jsonEncoder = json.NewEncoder(p.opts.w)
	}

	return p
}

const (
	tab     = "\t"
	newline = "\n"
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
	_, err := fmt.Fprint(p.opts.werr, fmt.Sprintf("%s\n", msg))
	return err
}

// GetPorts returns source and destination port of a flow.
func (p *Printer) GetPorts(f v1.Flow) (string, string) {
	l4 := f.GetL4()
	if l4 == nil {
		return "", ""
	}
	switch l4.Protocol.(type) {
	case *pb.Layer4_TCP:
		return p.TCPPort(layers.TCPPort(l4.GetTCP().SourcePort)), p.TCPPort(layers.TCPPort(l4.GetTCP().DestinationPort))
	case *pb.Layer4_UDP:
		return p.UDPPort(layers.UDPPort(l4.GetUDP().SourcePort)), p.UDPPort(layers.UDPPort(l4.GetUDP().DestinationPort))
	default:
		return "", ""
	}
}

// GetHostNames returns source and destination hostnames of a flow.
func (p *Printer) GetHostNames(f v1.Flow) (string, string) {
	var srcNamespace, dstNamespace, srcPodName, dstPodName, srcSvcName, dstSvcName string
	if f == nil || f.GetIP() == nil {
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
	return src, dst
}

func getTimestamp(f v1.Flow) string {
	if f == nil {
		return "N/A"
	}
	ts, err := types.TimestampFromProto(f.GetTime())
	if err != nil {
		return "N/A"
	}
	return MaybeTime(&ts)
}

// GetFlowType returns the type of a flow as a string.
func GetFlowType(f v1.Flow) string {
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
		switch f.GetVerdict() {
		case pb.Verdict_FORWARDED:
			return monitor.PolicyMatchType(f.GetPolicyMatchType()).String()
		case pb.Verdict_DROPPED:
			return api.DropReason(uint8(f.GetDropReason()))
		}
	}

	return "UNKNOWN"
}

// WriteProtoFlow writes v1.Flow into the output writer.
func (p *Printer) WriteProtoFlow(f v1.Flow) error {
	switch p.opts.output {
	case TabOutput:
		if p.line == 0 {
			_, err := fmt.Fprint(p.tw,
				"TIMESTAMP", tab,
				"SOURCE", tab,
				"DESTINATION", tab,
				"TYPE", tab,
				"VERDICT", tab,
				"SUMMARY", newline,
			)
			if err != nil {
				return err
			}
		}
		src, dst := p.GetHostNames(f)
		_, err := fmt.Fprint(p.tw,
			getTimestamp(f), tab,
			src, tab,
			dst, tab,
			GetFlowType(f), tab,
			f.GetVerdict().String(), tab,
			f.GetSummary(), newline,
		)
		if err != nil {
			return fmt.Errorf("failed to write out packet: %v", err)
		}
	case DictOutput:
		if p.line != 0 {
			// TODO: line length?
			_, err := fmt.Fprintln(p.opts.w, "------------")
			if err != nil {
				return err
			}
		}
		src, dst := p.GetHostNames(f)
		// this is a little crude, but will do for now. should probably find the
		// longest header and auto-format the keys
		_, err := fmt.Fprint(p.opts.w,
			"  TIMESTAMP: ", getTimestamp(f), newline,
			"     SOURCE: ", src, newline,
			"DESTINATION: ", dst, newline,
			"       TYPE: ", GetFlowType(f), newline,
			"    VERDICT: ", f.GetVerdict().String(), newline,
			"    SUMMARY: ", f.GetSummary(), newline,
		)
		if err != nil {
			return fmt.Errorf("failed to write out packet: %v", err)
		}
	case CompactOutput:
		src, dst := p.GetHostNames(f)
		_, err := fmt.Fprintf(p.opts.w,
			"%s [%s]: %s -> %s %s %s (%s)\n",
			getTimestamp(f),
			f.GetNodeName(),
			src,
			dst,
			GetFlowType(f),
			f.GetVerdict().String(),
			f.GetSummary(),
		)
		if err != nil {
			return fmt.Errorf("failed to write out packet: %v", err)
		}
	case JSONOutput:
		return p.jsonEncoder.Encode(f)
	}
	p.line++
	return nil
}

// MaybeTime returns a Millisecond precision timestamp, or "N/A" if nil.
func MaybeTime(t *time.Time) string {
	if t != nil {
		// TODO: support more date formats through options to `hubble observe`
		return t.Format(time.StampMilli)
	}
	return "N/A"
}

// UDPPort ...
func (p *Printer) UDPPort(port layers.UDPPort) string {
	i := int(port)
	if !p.opts.enablePortTranslation {
		return strconv.Itoa(i)
	}
	if name, ok := namedPorts[i]; ok {
		return fmt.Sprintf("%v(%v)", i, name)
	}
	return port.String()
}

// TCPPort ...
func (p *Printer) TCPPort(port layers.TCPPort) string {
	i := int(port)
	if !p.opts.enablePortTranslation {
		return strconv.Itoa(i)
	}
	if name, ok := namedPorts[i]; ok {
		return fmt.Sprintf("%v(%v)", i, name)
	}
	return port.String()
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
		return net.JoinHostPort(host, port)
	}

	return host
}
