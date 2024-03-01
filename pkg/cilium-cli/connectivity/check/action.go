// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	hubprinter "github.com/cilium/hubble/pkg/printer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/api/v1/relay"

	"github.com/cilium/cilium/pkg/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/utils/features"
)

const (
	testCommandRetries = 3
)

var (
	// PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
	pingHeaderPattern = regexp.MustCompile(`^PING .* bytes of data\.`)
)

// Action represents an individual action (e.g. a curl call) in a Scenario
// between a source and a destination peer.
type Action struct {
	// name of the Action
	name string

	// the Test this Action is executed in
	test *Test

	// the Scenario this Action belongs to
	scenario Scenario

	// src is the Pod used to execute the test from.
	src *Pod

	// Dst is the peer used as the destination for the action.
	dst TestPeer

	// IP family used in this Action
	ipFam features.IPFamily

	// expEgress is the expected test result for egress from the source pod
	expEgress Result

	// expIngress is the expected test result for the ingress in to the destination pod
	expIngress Result

	// flowsMu protects flows.
	flowsMu sync.Mutex
	// flows is a map of all flow logs generated during the Action.
	flows flowsSet

	// Should the action attempt to collect the flows with hubble
	CollectFlows bool

	flowResults map[TestPeer]FlowRequirementResults

	// started is the timestamp the test started
	started time.Time

	// failed is true when Fail was called on the Action
	failed bool

	// Output from action if there is any
	cmdOutput string

	// metricsPerSource collected at the initialisation of an Action.
	metricsPerSource promMetricsPerSource
}

func newAction(t *Test, name string, s Scenario, src *Pod, dst TestPeer, ipFam features.IPFamily) *Action {
	return &Action{
		name:             name,
		test:             t,
		scenario:         s,
		src:              src,
		dst:              dst,
		ipFam:            ipFam,
		CollectFlows:     true,
		flowResults:      map[TestPeer]FlowRequirementResults{},
		started:          time.Now(),
		failed:           false,
		cmdOutput:        "",
		metricsPerSource: make(promMetricsPerSource),
	}
}

func (a *Action) String() string {
	sn := a.test.scenarioName(a.scenario)
	p := a.Peers()
	if p != "" {
		return fmt.Sprintf("%s/%s: %s", sn, a.name, p)
	}

	return fmt.Sprintf("%s/%s", sn, a.name)
}

// Peers returns the name and addr:port of the peers involved in the Action.
// If source or destination peers are missing, returns an empty string.
func (a *Action) Peers() string {
	if a.src == nil || a.dst == nil {
		return ""
	}

	return fmt.Sprintf("%s (%s) -> %s (%s:%d)",
		a.src.Name(), a.src.Address(a.ipFam),
		a.dst.Name(), a.dst.Address(a.ipFam), a.dst.Port())
}

func (a *Action) Source() TestPeer {
	return a.src
}

func (a *Action) Destination() TestPeer {
	return a.dst
}

func (a *Action) CmdOutput() string {
	return a.cmdOutput
}

// IPFamily returns the IPFamily used for this test action.
func (a *Action) IPFamily() features.IPFamily {
	return a.ipFam
}

// Run executes function f.
//
// This method is to be called from a Scenario implementation.
func (a *Action) Run(f func(*Action)) {
	a.Logf("[.] Action [%s]", a)

	// Emit unbuffered progress indicator.
	a.test.progress()

	// Retrieve Prometheus metrics only if there are expectations.
	for _, m := range a.expIngress.Metrics {
		err := a.collectMetricsPerSource(m)
		if err != nil {
			a.Logf("❌ Failed to collect metrics for ingress from source %s: %w", m.Source, err)
		}

	}
	for _, m := range a.expEgress.Metrics {
		err := a.collectMetricsPerSource(m)
		if err != nil {
			a.Logf("❌ Failed to collect metrics for egress from source %s: %w", m.Source, err)
		}
	}

	// Only perform flow validation if a Hubble Relay connection is available.
	collectFlows := a.test.ctx.params.Hubble && a.CollectFlows && a.src != nil
	if collectFlows {
		// Channel for the flow listener to notify us when ready.
		ready := make(chan bool, 1)

		wg := sync.WaitGroup{}
		wg.Add(1)
		// TODO(timo): Use an actual context that can be cancelled by the user.
		// `Run()` should take context.
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			cancel()
			wg.Wait()
		}()

		// Start flow listener in the background.
		go func() {
			defer wg.Done()
			if err := a.followFlows(ctx, ready); err != nil {
				a.Fatalf("Receiving flows from Hubble Relay: %s", err)
			}
			a.Debug("Receiving flows from Hubble Relay gracefully closed down.")
		}()

		// Wait for at least one Hubble node to signal that it's ready so we don't
		// generate any traffic before it can be captured.
		timeout := time.NewTimer(30 * time.Second)
		defer timeout.Stop()

		select {
		case <-ready:
			timeout.Stop()
			a.Log("📄 Following flows...")
		case <-timeout.C:
			a.Fatalf("Timeout waiting for flow listener to become ready")
		}
	}

	// Execute the given test function.
	// Might call Fatal().
	f(a)

	// Print flow buffer if any failures or warnings occurred.
	// TODO(timo): printFlows is a misnomer, this function actually prints
	// the verdict annotated over the list of flows.
	if collectFlows && (a.test.ctx.PrintFlows() || a.failed) {
		a.printFlows(a.Source())
		a.printFlows(a.Destination())
	}
}

// collectMetricsPerSource retrieves metrics for the given source.
func (a *Action) collectMetricsPerSource(m MetricsResult) error {
	if _, ok := a.metricsPerSource[m.Source.Name]; !ok {
		metrics, err := a.collectPrometheusMetrics(m.Source)
		if err != nil {
			return err
		}
		a.metricsPerSource[m.Source.Name] = metrics
	}
	return nil
}

// fail marks the Action as failed.
func (a *Action) fail() {
	a.failed = true
}

// WriteDataToPod writes data to a file in the source pod
// It does this by using a shell command, writing huge files should be avoided
func (a *Action) WriteDataToPod(ctx context.Context, filePath string, data []byte) {
	if err := ctx.Err(); err != nil {
		a.Fatal("Skipping writing data to pod:", ctx.Err())
	}

	// Encode data to base64 to be decoded in the shell
	encodedData := base64.StdEncoding.EncodeToString(data)

	if a.src == nil {
		a.Fatalf("No source Pod to add file to: %s", filePath)
	}
	pod := a.src

	output, err := pod.K8sClient.ExecInPod(ctx,
		pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"],
		[]string{"sh", "-c", fmt.Sprintf("echo %s | base64 -d > %s", encodedData, filePath)})

	if err != nil {
		a.Fatalf("Writing data to pod failed: %s: %s", err, output.String())
	}
}

func (a *Action) ExecInPod(ctx context.Context, cmd []string) {
	if err := ctx.Err(); err != nil {
		a.Fatal("Skipping command execution:", ctx.Err())
	}

	// Tests need a source Pod to execute in.
	if a.src == nil {
		a.Fatalf("No source Pod to execute command from: %s", cmd)
	}
	pod := a.src

	a.Debug("Executing command", cmd)
	cmdName := cmd[0]
	cmdStr := strings.Join(cmd, " ")

	var output bytes.Buffer
	var err error
	// We retry the command in case of inconclusive results. The result is
	// deemed inconclusive when the command succeeded, but we don't have any
	// output. We've seen this happen when there are connectivity blips on the
	// k8s side.
	// Ping Command is treated specially: its output may contain the header
	// `PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.` even if the command hangs.
	// This check currently only works because all our test commands expect an
	// output.
	for i := 1; i <= testCommandRetries; i++ {
		output, err = pod.K8sClient.ExecInPod(ctx,
			pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"], cmd)
		a.cmdOutput = output.String()
		// Check for inconclusive results.
		if err == nil && strings.TrimSpace(pingHeaderPattern.ReplaceAllString(output.String(), "")) == "" {
			a.Debugf("retrying command %s due to inconclusive results", cmdStr)
			continue
		}
		break
	}
	// Check for inconclusive results.
	if err == nil && strings.TrimSpace(pingHeaderPattern.ReplaceAllString(output.String(), "")) == "" {
		a.Failf("inconclusive results: command %q was successful but without output", cmdStr)
	}

	showOutput := false
	expectedExitCode := a.expectedExitCode()
	if err != nil {
		if expectedExitCode == 0 {
			// Command failed unexpectedly, display output.
			a.Failf("command %q failed: %s", cmdStr, err)
			showOutput = true
		} else {
			exitCode, extractErr := a.extractExitCode(err)
			if extractErr != nil {
				a.test.Info(extractErr.Error())
			}
			if expectedExitCode == ExitAnyError || exitCode == expectedExitCode {
				a.test.Debugf("command %q failed as expected: %s", cmdStr, err)
			} else {
				a.Failf("command %q failed with unexpected exit code: %s (expected %d, found %d)", cmdStr, err, expectedExitCode, exitCode)
			}
		}
	} else {
		if expectedExitCode != 0 {
			// Command succeeded unexpectedly, display output.
			a.Failf("command %q succeeded while it should have failed: %s", cmdStr, output.String())
			showOutput = true
		}
	}
	if showOutput {
		a.test.Infof("%s output:", cmdName)
		a.test.Log(strings.TrimSpace(output.String()))
		a.test.Log()
	}
}

var exitCodeRegex = regexp.MustCompile("exit code ([0-9]+)")

// extractExitCode extracts command exit code from ExecInPod() error output
func (a *Action) extractExitCode(err error) (ExitCode, error) {
	// Extract exit code from 'err'
	m := exitCodeRegex.FindStringSubmatch(err.Error())
	if len(m) != 2 || len(m[1]) == 0 {
		return ExitInvalidCode, fmt.Errorf("unable to extract exit code from error: %s", err.Error())
	}
	i, err := strconv.Atoi(m[1])
	if err != nil {
		return ExitInvalidCode, fmt.Errorf("invalid exit code %q in error %s", m[1], err.Error())
	}
	if i < 0 || i > 255 {
		return ExitInvalidCode, fmt.Errorf("exit code %q out of range [0-255]", m[1])
	}
	return ExitCode(i), nil
}

// expectedExitCode returns the expected shell exit code, or ExitAnyError for any value between 1-255.
func (a *Action) expectedExitCode() ExitCode {
	if a.expEgress.ExitCode == 0 && a.expIngress.ExitCode == 0 {
		return 0 // success
	}
	// If egress and ingress expect the command to fail in different
	// ways egress enforcement will cause the command to fail first.
	if a.expEgress.ExitCode != 0 {
		return a.expEgress.ExitCode
	}
	return a.expIngress.ExitCode
}

func (a *Action) printFlows(peer TestPeer) {
	if len(a.flows) == 0 {
		a.Logf("📄 No flows recorded for peer %s during action %s", peer.Name(), a.name)
		return
	}

	a.Logf("📄 Flow logs for peer %s:", peer.Name())
	printer := hubprinter.New(hubprinter.Compact(), hubprinter.WithIPTranslation())
	defer printer.Close()

	r := a.flowResults[peer]

	for index, flow := range a.flows {
		if !a.test.ctx.AllFlows() && r.FirstMatch > 0 && r.FirstMatch > index {
			// Skip flows before the first match unless printing all flows
			continue
		}

		if !a.test.ctx.AllFlows() && r.LastMatch > 0 && r.LastMatch < index {
			// Skip flows after the last match unless printing all flows
			continue
		}

		f := flow.Flow

		src, dst := printer.GetHostNames(f)

		ts := "N/A"
		if t := f.GetTime(); t != nil && t.IsValid() {
			ts = t.AsTime().Format(time.StampMilli)
		}

		flowPrefix := "❓"
		if expect, ok := r.Matched[index]; ok {
			if expect {
				flowPrefix = "✅"
			} else {
				flowPrefix = "❌"
			}
		}

		//nolint:staticcheck // Summary is deprecated but there is no real alternative yet
		//lint:ignore SA1019 Summary is deprecated but there is no real alternative yet
		a.Logf("%s [%d] %s: %s -> %s %s %s %s %s (%s)", flowPrefix, index, ts, src, dst, hubprinter.GetFlowType(f), f.Verdict.String(), f.TrafficDirection, f.DropReasonDesc, f.Summary)
	}

	a.Log()
}

func (a *Action) matchFlowRequirements(flows flowsSet, req *filters.FlowSetRequirement) FlowRequirementResults {
	var offset int
	r := FlowRequirementResults{Failures: -1} // -1 to get the loop started

	match := func(expect bool, f filters.FlowRequirement, fc *filters.FlowContext) (int, bool, *flow.Flow) {
		index, match, flow := flows[offset:].Contains(f.Filter, fc)
		index += offset

		if match {
			r.Matched[index] = expect

			// Update last match index and timestamp
			if r.LastMatch < index {
				r.LastMatch = index
				if t := flow.GetTime(); t != nil && t.IsValid() {
					r.LastMatchTimestamp = t.AsTime()
				}
			}
		}

		if match != expect {
			msgSuffix := "not found"
			if match {
				msgSuffix = fmt.Sprintf("found at %d", index)
			}

			a.Infof("%s %s %s", f.Msg, f.Filter.String(fc), msgSuffix)

			// Record the failure in the results of the current match attempt.
			r.Failures++
		} else {
			msgSuffix := "not found"
			if match {
				msgSuffix = fmt.Sprintf("found at %d", index)
			}

			a.Logf("✅ %s %s", f.Msg, msgSuffix)
		}

		return index, match, flow
	}

	for r.NeedMoreFlows || r.Failures != 0 {
		// reinit for the new round
		r.NeedMoreFlows = false
		r.Failures = 0
		r.Matched = MatchMap{}
		r.FirstMatch = -1
		r.LastMatch = -1

		flowCtx := filters.NewFlowContext()

		index, matched, _ := match(true, req.First, &flowCtx)
		if !matched {
			r.NeedMoreFlows = true
			// No point trying to match more if First does not match.
			break
		}
		r.FirstMatch = index

		for _, f := range req.Middle {
			if f.SkipOnAggregation && a.test.ctx.FlowAggregation() {
				continue
			}
			// "middle" flows can appear out of order due to e.g.,
			// L7 flows being delivered from a proxy vs. SYN/FIN
			// being delivered from the datapath. Allow for this
			// by requesting more flows also when any of the
			// "middle" matches fail.
			if _, match, _ := match(true, f, &flowCtx); !match {
				r.NeedMoreFlows = true
			}
		}

		if !(req.Last.SkipOnAggregation && a.test.ctx.FlowAggregation()) {
			if _, match, _ := match(true, req.Last, &flowCtx); !match {
				r.NeedMoreFlows = true
			}
		}

		for _, f := range req.Except {
			match(false, f, &flowCtx)
		}

		// Check if successfully fully matched
		if !r.NeedMoreFlows && r.Failures == 0 {
			break
		}

		// Try if some other flow instance would find both first and last required flows
		offset = r.FirstMatch + 1
	}
	return r
}

func (a *Action) GetEgressRequirements(p FlowParameters) (reqs []filters.FlowSetRequirement) {
	srcIP := a.src.Address(a.ipFam)
	dstIP := a.dst.Address(a.ipFam)
	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipRequest := filters.IP(srcIP, dstIP)
	ipResponse := filters.IP(dstIP, srcIP)
	if len(p.AltDstIP) != 0 && p.AltDstIP != dstIP {
		ipRequest = filters.Or(filters.IP(srcIP, p.AltDstIP), ipRequest)
		ipResponse = filters.Or(filters.IP(p.AltDstIP, srcIP), ipResponse)
	}

	var egress filters.FlowSetRequirement
	var http filters.FlowSetRequirement
	haveHTTP := false

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if a.expEgress.Drop || a.expEgress.EgressDrop {
			dropFilter := filters.Drop()
			if a.expEgress.EgressDrop {
				dropFilter = filters.Drop(filters.WithEgress(), filters.WithDropFunc(a.expEgress.DropReasonFunc))
			}
			egress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, dropFilter), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			if a.expIngress.Drop || a.expIngress.IngressDrop {
				dropFilter := filters.Drop()
				if a.expEgress.IngressDrop {
					dropFilter = filters.Drop(filters.WithIngress(), filters.WithDropFunc(a.expIngress.DropReasonFunc))
				}

				// If ingress drops is in the same node we get the drop flows also for egress, tolerate that
				egress = filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last: filters.FlowRequirement{Filter: filters.Or(filters.And(ipResponse, icmpResponse), filters.And(ipRequest, icmpRequest,
						dropFilter)), Msg: "ICMP response or request drop", SkipOnAggregation: true},
				}
			} else {
				egress = filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
					Except: []filters.FlowRequirement{
						{Filter: filters.And(filters.Or(filters.And(ipResponse, icmpResponse), filters.And(ipRequest, icmpRequest)), filters.Drop()), Msg: "Drop"},
					},
				}
			}
		}
	case TCP:
		tcpRequest := filters.TCP(0, a.dst.Port())
		tcpResponse := filters.TCP(a.dst.Port(), 0)
		if p.AltDstPort != 0 && p.AltDstPort != a.dst.Port() {
			tcpRequest = filters.Or(filters.TCP(0, p.AltDstPort), tcpRequest)
			tcpResponse = filters.Or(filters.TCP(p.AltDstPort, 0), tcpResponse)
		}

		if (a.expEgress.Drop || a.expEgress.EgressDrop) && !a.expEgress.L7Proxy {
			dropFilter := filters.Drop()
			if a.expEgress.EgressDrop {
				dropFilter = filters.Drop(filters.WithEgress(), filters.WithDropFunc(a.expEgress.DropReasonFunc))
			}
			// L3/L4 drop
			egress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, dropFilter), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				},
			}
		} else {
			egress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Middle: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK", SkipOnAggregation: true},
				},
				// Either side may FIN first
				Last: filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Drop()), Msg: "L3/L4 Drop"},
				},
			}
			if p.RSTAllowed {
				// For the connection termination, we will either see:
				// a) FIN + FIN b) FIN + RST c) RST
				// Either side may RST or FIN first
				egress.Last = filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Or(filters.FIN(), filters.RST())), Msg: "FIN or RST", SkipOnAggregation: true}
			} else {
				egress.Except = append(egress.Except, filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.RST()), Msg: "RST"})
			}
			if a.expEgress.L7Proxy || a.expEgress.HTTP.Status != "" || a.expEgress.HTTP.Method != "" || a.expEgress.HTTP.URL != "" {
				// HTTP access logs may come from a separate Envoy proxy upstream connection which may be
				// kept open. Add a separate flow requirement with FIN filter replaced with a L7/HTTP
				// filter to allow for both a separate connection and a missing FIN.
				http = egress
				haveHTTP = true
				if a.expEgress.Drop {
					// L7 drop
					http.Last = filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.L7Drop()), Msg: "L7 Drop"}
				} else if a.expEgress.HTTP.Status != "" || a.expEgress.HTTP.Method != "" || a.expEgress.HTTP.URL != "" {
					code := uint32(math.MaxUint32)
					if s, err := strconv.Atoi(a.expEgress.HTTP.Status); err == nil {
						code = uint32(s)
					}
					http.Last = filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.HTTP(code, a.expEgress.HTTP.Method, a.expEgress.HTTP.URL)), Msg: "HTTP"}
				}
			}
		}
	case UDP:
		a.Fail("UDP egress flow matching not implemented yet")
	default:
		a.Failf("Invalid egress flow matching protocol %d", p.Protocol)
	}

	if p.DNSRequired || a.expEgress.DNSProxy {
		// Override to allow for any DNS server
		ipRequest := filters.IP(srcIP, "")
		ipResponse := filters.IP("", srcIP)

		dnsRequest := filters.Or(filters.UDP(0, 53), filters.TCP(0, 53))
		dnsResponse := filters.Or(filters.UDP(53, 0), filters.TCP(53, 0))

		dns := filters.FlowSetRequirement{First: filters.FlowRequirement{Filter: filters.And(ipRequest, dnsRequest), Msg: "DNS request"}}
		if a.expEgress.DNSProxy {
			qname := a.dst.Address(a.ipFam) + "."
			dns.Middle = []filters.FlowRequirement{{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"}}
			dns.Last = filters.FlowRequirement{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(qname, 0)), Msg: "DNS proxy"}
			// 5 is the default rcode returned on error such as policy deny
			dns.Except = []filters.FlowRequirement{{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(qname, 5)), Msg: "DNS proxy DROP"}}
		} else {
			dns.Last = filters.FlowRequirement{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"}
		}

		reqs = append(reqs, dns)
	}
	reqs = append(reqs, egress)
	if haveHTTP {
		reqs = append(reqs, http)
	}

	return reqs
}

func (a *Action) GetIngressRequirements(p FlowParameters) []filters.FlowSetRequirement {
	var ingress filters.FlowSetRequirement
	if a.expIngress.None {
		return []filters.FlowSetRequirement{}
	}

	srcIP := a.src.Address(a.ipFam)
	dstIP := a.dst.Address(a.ipFam)
	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipResponse := filters.IP(dstIP, srcIP)
	ipRequest := filters.IP(srcIP, dstIP)
	if len(p.AltDstIP) != 0 && p.AltDstIP != dstIP {
		ipResponse = filters.Or(filters.IP(p.AltDstIP, srcIP), ipResponse)
		ipRequest = filters.Or(filters.IP(srcIP, p.AltDstIP), ipRequest)
	}

	tcpRequest := filters.TCP(0, a.dst.Port())
	tcpResponse := filters.TCP(a.dst.Port(), 0)
	if p.AltDstPort != 0 {
		tcpRequest = filters.Or(filters.TCP(0, p.AltDstPort), tcpRequest)
		tcpResponse = filters.Or(filters.TCP(p.AltDstPort, 0), tcpResponse)
	}

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if a.expIngress.Drop || a.expIngress.IngressDrop {
			dropFilter := filters.Drop()
			if a.expIngress.IngressDrop {
				dropFilter = filters.Drop(filters.WithIngress(), filters.WithDropFunc(a.expIngress.DropReasonFunc))
			}
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, dropFilter), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				},
			}
		}
	case TCP:
		if a.expIngress.Drop || a.expIngress.IngressDrop {
			dropFilter := filters.Drop()
			if a.expIngress.IngressDrop {
				dropFilter = filters.Drop(filters.WithIngress(), filters.WithDropFunc(a.expIngress.DropReasonFunc))
			}
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, dropFilter), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				},
			}
		} else {
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Middle: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
				},
				// Either side may FIN first
				Last: filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.RST()), Msg: "RST"},
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Drop()), Msg: "Drop"},
				},
			}
		}
	case UDP:
		a.Fail("UDP ingress flow matching not implemented yet")
	default:
		a.Failf("Invalid ingress flow matching protocol %d", p.Protocol)
	}

	return []filters.FlowSetRequirement{ingress}
}

func (a *Action) isRelayServerStatusOk(ctx context.Context, client observer.ObserverClient) bool {
	// Sometimes ServerStatus request just gets stuck until the context gets cancelled. Call
	// ServerStatus with a shorter timeout than ctx so that we get to try it multiple times.
	timeoutContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := client.ServerStatus(timeoutContext, &observer.ServerStatusRequest{})
	if err == nil {
		a.Debugf("hubble relay server status %+v", res)
		if (res.NumUnavailableNodes == nil || res.NumUnavailableNodes.Value == 0) && res.NumFlows > 0 {
			// This means all the nodes are available, and Hubble Relay started receiving flows.
			// Ideally we should check res.NumConnectedNodes matches the expected number of Cilium
			// nodes instead of relying on res.NumUnavailableNodes, but I don't know if that information
			// is available to us.
			return true
		}
	} else {
		a.Debugf("hubble relay server status failed: %v", err)
	}
	return false
}

// waitForRelay polls the server status from Relay until it indicates that there are no unavailable
// nodes and num_flows is greater than zero (success), or the context is cancelled (failure).
func (a *Action) waitForRelay(ctx context.Context, client observer.ObserverClient) error {
	for {
		if a.isRelayServerStatusOk(ctx, client) {
			a.Debug("hubble relay is ready")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("hubble server status failure: %w", ctx.Err())
		case <-time.After(time.Second):
			a.Debug("retrying hubble relay server status request")
		}
	}
}

// followFlows starts a long-poll against Hubble for receiving all flow logs
// pertaining to the Action's Pod until ctx is canceled.
// Signals on the ready channel when the listener is ready to report traffic.
// Returns error if any Hubble nodes return errors or are unavailable, or if
// anything unexpected occurs during the follow operation.
func (a *Action) followFlows(ctx context.Context, ready chan bool) error {
	// Need a Hubble client to receive flows.
	hubbleClient := a.test.ctx.HubbleClient()
	if hubbleClient == nil {
		// This function is supposed to be called only if Hubble is enabled. Return an error
		// if Hubble client is not initialized.
		return fmt.Errorf("hubble client is not initialized")
	}
	// A sanity check to ensure Relay is connected to all the Hubble instances.
	if err := a.waitForRelay(ctx, hubbleClient); err != nil {
		return err
	}

	// All tests are initiated from the source Pod, so filtering traffic
	// originating from and destined to the Pod should capture what we need.
	pod := a.Source()
	filter := pod.FlowFilters()

	// Initiate long-poll against Hubble Relay.
	b, err := hubbleClient.GetFlows(ctx, &observer.GetFlowsRequest{
		Whitelist: filter,
		Follow:    true,
	})
	if err != nil {
		return fmt.Errorf("initiating follow request: %w", err)
	}

	// Only send readiness signal once.
	var once sync.Once

	for {
		// Blocks, interruptable by context cancelation.
		res, err := b.Recv()
		if err != nil {
			// Any of the following errors are expected and signal the end
			// of the read loop.
			if errors.Is(err, io.EOF) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				a.Debugf("Hubble polling ended: %v", err)
				return nil
			}

			// Return gracefully on 'canceled' gRPC error.
			if status.Code(err) == codes.Canceled {
				a.Debugf("Hubble polling ended: %v", err)
				return nil
			}

			return fmt.Errorf("gRPC error: %w", err)
		}

		switch r := res.GetResponseTypes().(type) {

		case *observer.GetFlowsResponse_NodeStatus:
			// Handle NodeStatus messages generated by Hubble peers, containing
			// individual node readiness, unavailability, invalid filters etc.

			switch r.NodeStatus.StateChange {
			case relay.NodeState_NODE_CONNECTED:
				// Received first connection event from a Hubble peer, tentatively
				// notify the caller that traffic can be generated.
				a.Debugf("Connected to Hubble node(s) %s", r.NodeStatus.NodeNames)
				once.Do(func() { ready <- true })

			case relay.NodeState_NODE_UNAVAILABLE:
				// An unavailable node will result in the event log being incomplete,
				// so the test needs to be aborted.
				return fmt.Errorf("unavailable node(s) %s, flow results will be incomplete", r.NodeStatus.NodeNames)

			case relay.NodeState_NODE_ERROR:
				// When an invalid filter is specified, a node error will be published
				// by at least one Hubble node.
				return fmt.Errorf("node error: %s", r.NodeStatus.Message)
			}

		case *observer.GetFlowsResponse_Flow:
			// Store any flows we receive in the Action to be sent off
			// to the flow matcher later.

			a.flowsMu.Lock()
			a.flows = append(a.flows, r)
			a.flowsMu.Unlock()

		default:
			// Abort on any unknown message types.
			return fmt.Errorf("received unknown message: %q", r)

		}
	}
}

// matchAllFlowRequirements takes a list of flow requirements and matches each
// of them against the flows logged against the Action up to this point.
// Returns the merged verdict of all matcher operations using all requirements.
func (a *Action) matchAllFlowRequirements(reqs []filters.FlowSetRequirement) FlowRequirementResults {
	//TODO(timo): Reduce complexity of matcher output to make the surrounding logic
	// easier to comprehend and modify. Different properties of the verdict should
	// be exposed as methods, otherwise subtle bugs slip into the surrounding code
	// due to the combinations of failures/firstmatch/needmoreflows, etc.
	// The logic needs some cleanup in general and is in dire need of tests.

	out := FlowRequirementResults{
		FirstMatch:    -1,
		LastMatch:     -1,
		NeedMoreFlows: false,
	}

	if len(reqs) == 0 {
		return out
	}

	if len(a.flows) == 0 {
		out.NeedMoreFlows = true
		return out
	}
	a.flowsMu.Lock()
	defer a.flowsMu.Unlock()

	for i := range reqs {
		res := a.matchFlowRequirements(a.flows, &reqs[i])
		//TODO(timo): The matcher should probably take in all requirements
		// and return its verdict in a single struct.
		out.Merge(&res)
	}

	return out
}

// ValidateFlows retrieves the flow pods of the specified pod and validates
// that all filters find a match. On failure, t.Fail() is called.
func (a *Action) ValidateFlows(ctx context.Context, peer TestPeer, reqs []filters.FlowSetRequirement) {
	//TODO(timo): Create a single source of truth for checking whether we
	// need to perform flow validation or not.
	if a.test.ctx.params.FlowValidation == FlowValidationModeDisabled {
		return
	}

	hubbleClient := a.test.ctx.HubbleClient()
	if hubbleClient == nil {
		return
	}

	// There can be an empty list of flow requirements for some tests, in which
	// case we should not perform validation.
	if len(reqs) == 0 {
		a.Debugf("No flow requirements to validate for peer %s", peer.Name())
		return
	}

	a.Logf("📄 Validating flows for peer %s", peer.Name())
	res := a.validateFlowsForPeer(ctx, reqs)

	// Store the validation result for the given peer.
	a.flowResults[peer] = res

	if res.Failures == 0 && res.FirstMatch >= 0 {
		a.Logf("✅ Flow validation successful for peer %s (first: %d, last: %d, matched: %d)", peer.Name(), res.FirstMatch, res.LastMatch, len(res.Matched))
	} else {
		a.Failf("Flow validation failed for peer %s: %d failures (first: %d, last: %d, matched: %d)", peer.Name(), res.Failures, res.FirstMatch, res.LastMatch, len(res.Matched))
	}
}

func (a *Action) validateFlowsForPeer(ctx context.Context, reqs []filters.FlowSetRequirement) FlowRequirementResults {
	var res FlowRequirementResults

	interval := time.NewTicker(defaults.FlowRetryInterval)
	defer interval.Stop()

	ctx, cancel := context.WithTimeout(ctx, defaults.FlowWaitTimeout)
	defer cancel()

	for {
		select {
		// Attempt to validate all flows received during the Action so far,
		// once per validation interval.
		case <-interval.C:
			if len(a.flows) == 0 {
				// Suppress output like 'Validating 0 flows against 2 requirements'
				// as it is futile to validate requirements when there are no flows yet.
				continue
			}
			a.Debugf("Validating %d flows against %d requirements", len(a.flows), len(reqs))

			res = a.matchAllFlowRequirements(reqs)
			if !res.NeedMoreFlows && res.FirstMatch != -1 {
				// TODO(timo): This success condition should be a method on FlowRequirementResults.
				return res
			}
		case <-ctx.Done():
			a.Fail("Aborting flow matching:", ctx.Err())
			return res
		}
	}
}
func (a *Action) GetEgressMetricsRequirements() []MetricsResult {
	return a.expEgress.Metrics
}
func (a *Action) GetIngressMetricsRequirements() []MetricsResult {
	return a.expIngress.Metrics
}

const (
	metricsCollectionTimeout      = time.Second * 30
	metricCollectionIntervalRetry = time.Second * 5
)

// ValidateMetrics confronts the expected metrics against the last ones retrieves.
func (a *Action) ValidateMetrics(ctx context.Context, pod Pod, results []MetricsResult) {
	node := pod.NodeName()

	if len(results) == 0 {
		// Early exit.
		a.Debugf("no metrics requirements to validate for this node %s", node)
		return
	}

	for _, r := range results {
		a.validateMetric(ctx, node, r)
	}
}

func (a *Action) validateMetric(ctx context.Context, node string, result MetricsResult) {
	if result.IsEmpty() {
		a.Debugf("there is no source configured to retrieve metrics for node %s", node)
		return
	}

	// ctx is used here as the duration of the retries to collect metrics.
	ctx, cancel := context.WithTimeout(ctx, metricsCollectionTimeout)
	defer cancel()

	// ticker here is used as the interval duration before the next retry.
	ticker := time.NewTicker(metricCollectionIntervalRetry)
	defer ticker.Stop()

	for {
		// Collect the new metrics.
		newMetrics, err := a.collectPrometheusMetricsForNode(result.Source, node)
		if err != nil {
			a.Failf("failed to collect new metrics on node %s: %w", node, err)
			return
		}

		// Check the metrics comparing the first retrieved metrics and the new ones.
		err = result.Assert(a.metricsPerSource[result.Source.Name][node], newMetrics)
		if err != nil {
			a.Debugf("failed to check metrics on node %s: %s\n", node, err)
		} else {
			// Metrics check succeed, let's exit.
			a.Debugf("checked metrics properly on node %s\n", node)
			return

		}

		select {
		case <-ctx.Done():
			// Context timeout is reached, let's exit.
			a.Failf("failed to collect metrics on node %s, context timeout: %s\n", node, ctx.Err())
			return
		case <-ticker.C:
			// Ticker is delivered, let's retry.
		}
	}
}
