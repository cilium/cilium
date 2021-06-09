// Copyright 2020-2021 Authors of Cilium
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

package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	hubprinter "github.com/cilium/hubble/pkg/printer"
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

	// expEgress is the expected test result for egress from the source pod
	expEgress Result

	// expIngress is the expected test result for the ingress in to the destination pod
	expIngress Result

	// flows is a map of all flow logs, indexed by pod name
	flows map[string]flowsSet

	flowResults map[string]FlowRequirementResults

	// started is the timestamp the test started
	started time.Time

	// failed is true when Fail was called on the Action
	failed bool

	// warned is true when Warn was called on the Action
	warned bool
}

func newAction(t *Test, name string, s Scenario, src *Pod, dst TestPeer) *Action {
	return &Action{
		name:        name,
		test:        t,
		scenario:    s,
		src:         src,
		dst:         dst,
		started:     time.Now(),
		flows:       map[string]flowsSet{},
		flowResults: map[string]FlowRequirementResults{},
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
		a.src.Name(), a.src.Address(),
		a.dst.Name(), a.dst.Address(), a.dst.Port())
}

func (a *Action) Source() TestPeer {
	return a.src
}

func (a *Action) Destination() TestPeer {
	return a.dst
}

// Run executes function f.
//
// This method is to be called from a Scenario implementation.
func (a *Action) Run(f func(*Action)) {
	a.Logf("[.] Action [%s]", a)

	// Execute the given test function.
	// Might call Fatal().
	f(a)

	// Print flow buffer if any failures or warnings occur.
	if a.test.ctx.PrintFlows() || a.failed || a.warned {
		for name, flows := range a.flows {
			a.printFlows(name, flows, a.flowResults[name])
		}
	}
}

// fail marks the Action as failed.
func (a *Action) fail() {
	a.failed = true
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

	// Warning: ExecInPod* does not use ctx, command cannot be cancelled.
	stdout, stderr, err := pod.K8sClient.ExecInPodWithStderr(context.TODO(),
		pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"], cmd)

	cmdName := cmd[0]
	cmdStr := strings.Join(cmd, " ")

	if stderr.Len() > 0 {
		a.test.Debugf("%s stderr: %s", cmdName, stderr.String())
	} else if stdout.Len() > 0 {
		a.test.Debugf("%s stdout: %s", cmdName, stdout.String())
	}

	if err != nil || stderr.Len() > 0 {
		if a.shouldSucceed() {
			a.Failf("command %q failed: %s", cmdStr, err)
		} else {
			a.test.Debugf("command %q failed as expected: %s", cmdStr, err)
		}
	} else {
		if !a.shouldSucceed() {
			a.Failf("command %q succeeded while it should have failed: %s", cmdStr, stdout.String())
		}
	}
}

// shouldSucceed returns true if no drops are expected in either direction.
func (a *Action) shouldSucceed() bool {
	return !a.expEgress.Drop && !a.expIngress.Drop
}

func (a *Action) printFlows(pod string, f flowsSet, r FlowRequirementResults) {
	if len(f) == 0 {
		a.Logf("📄 No flows recorded for pod %s", pod)
		return
	}

	a.Logf("📄 Flow logs for pod %s:", pod)
	printer := hubprinter.New(hubprinter.Compact(), hubprinter.WithIPTranslation())
	defer printer.Close()

	for index, flow := range f {
		if !a.test.ctx.AllFlows() && r.FirstMatch > 0 && r.FirstMatch > index {
			// Skip flows before the first match unless printing all flows
			continue
		}

		if !a.test.ctx.AllFlows() && r.LastMatch > 0 && r.LastMatch < index {
			// Skip flows after the last match unless printing all flows
			continue
		}

		f := flow.GetFlow()

		src, dst := printer.GetHostNames(f)

		ts := "N/A"
		flowTimestamp, err := ptypes.Timestamp(f.GetTime())
		if err == nil {
			ts = flowTimestamp.Format(time.StampMilli)
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
		a.Logf("%s [%d] %s: %s -> %s %s %s (%s)", flowPrefix, index, ts, src, dst, hubprinter.GetFlowType(f), f.Verdict.String(), f.Summary)
	}

	a.Log()
}

func (a *Action) matchFlowRequirements(ctx context.Context, flows flowsSet, offset int, pod string, req *filters.FlowSetRequirement) (r FlowRequirementResults) {
	r.Matched = MatchMap{}
	r.FirstMatch = -1
	r.LastMatch = -1

	// Skip 'offset' flows
	flows = flows[offset:]
	flowCtx := filters.NewFlowContext()

	match := func(expect bool, f filters.FlowRequirement, fc *filters.FlowContext) (int, bool, *flow.Flow) {
		index, match, flow := flows.Contains(f.Filter, fc)

		if match {
			r.Matched[offset+index] = expect

			// Update last match index and timestamp
			if r.LastMatch < offset+index {
				r.LastMatch = offset + index
				flowTimestamp, err := ptypes.Timestamp(flow.Time)
				if err == nil {
					r.LastMatchTimestamp = flowTimestamp
				}
			}
		}

		if match != expect {
			msgSuffix := "not found"
			if match {
				msgSuffix = fmt.Sprintf("found at %d", offset+index)
			}

			a.Infof("%s %s %s", f.Msg, f.Filter.String(fc), msgSuffix)

			// Record the failure in the results of the current match attempt.
			r.Failures++
		} else {
			msgSuffix := "not found"
			if match {
				msgSuffix = fmt.Sprintf("found at %d", offset+index)
			}

			a.Logf("✅ %s %s", f.Msg, msgSuffix)
		}

		return index, match, flow
	}

	if index, match, _ := match(true, req.First, &flowCtx); !match {
		r.NeedMoreFlows = true
		// No point trying to match more if First does not match.
		return
	} else {
		r.FirstMatch = offset + index
	}

	for _, f := range req.Middle {
		if f.SkipOnAggregation && a.test.ctx.FlowAggregation() {
			continue
		}
		match(true, f, &flowCtx)
	}

	if !(req.Last.SkipOnAggregation && a.test.ctx.FlowAggregation()) {
		if _, match, _ := match(true, req.Last, &flowCtx); !match {
			r.NeedMoreFlows = true
		}
	}

	for _, f := range req.Except {
		match(false, f, &flowCtx)
	}

	return
}

func (a *Action) GetEgressRequirements(p FlowParameters) (reqs []filters.FlowSetRequirement) {
	var egress filters.FlowSetRequirement
	srcIP := a.src.Address()
	dstIP := a.dst.Address()

	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipResponse := filters.IP(dstIP, srcIP)
	ipRequest := filters.IP(srcIP, dstIP)

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if a.expEgress.Drop {
			egress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			if a.expIngress.Drop {
				// If ingress drops is in the same node we get the drop flows also for egress, tolerate that
				egress = filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last:  filters.FlowRequirement{Filter: filters.Or(filters.And(ipResponse, icmpResponse), filters.And(ipRequest, icmpRequest, filters.Drop())), Msg: "ICMP response or request drop", SkipOnAggregation: true},
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
		if p.NodePort != 0 {
			tcpRequest = filters.Or(filters.TCP(0, p.NodePort), tcpRequest)
			tcpResponse = filters.Or(filters.TCP(p.NodePort, 0), tcpResponse)
		}

		if a.expEgress.Drop {
			egress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.Drop()), Msg: "Drop"},
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
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Drop()), Msg: "Drop"},
				},
			}
			if a.expEgress.HTTP.Status != "" || a.expEgress.HTTP.Method != "" || a.expEgress.HTTP.URL != "" {
				code, err := strconv.Atoi(a.expEgress.HTTP.Status)
				if err != nil {
					code = math.MaxUint32
				}
				egress.Middle = append(egress.Middle, filters.FlowRequirement{Filter: filters.HTTP(uint32(code), a.expEgress.HTTP.Method, a.expEgress.HTTP.URL), Msg: "HTTP"})
			}
			if p.RSTAllowed {
				// For the connection termination, we will either see:
				// a) FIN + FIN b) FIN + RST c) RST
				// Either side may RST or FIN first
				egress.Last = filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Or(filters.FIN(), filters.RST())), Msg: "FIN or RST", SkipOnAggregation: true}
			} else {
				egress.Except = append(egress.Except, filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.RST()), Msg: "RST"})
			}
		}
	case UDP:
		a.Fail("UDP egress flow matching not implemented yet")
	default:
		a.Failf("Invalid egress flow matching protocol %d", p.Protocol)
	}
	reqs = append(reqs, egress)

	if p.DNSRequired || a.expEgress.DNSProxy {
		dnsRequest := filters.Or(filters.UDP(0, 53), filters.TCP(0, 53))
		dnsResponse := filters.Or(filters.UDP(53, 0), filters.TCP(53, 0))

		dns := filters.FlowSetRequirement{First: filters.FlowRequirement{Filter: filters.And(ipRequest, dnsRequest), Msg: "DNS request"}}
		if a.expEgress.DNSProxy {
			dns.Middle = []filters.FlowRequirement{{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"}}
			dns.Last = filters.FlowRequirement{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(a.dst.Address()+".", 0)), Msg: "DNS proxy"}
		} else {
			dns.Last = filters.FlowRequirement{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"}
		}
		reqs = append(reqs, dns)
	}

	return reqs
}

func (a *Action) GetIngressRequirements(p FlowParameters) []filters.FlowSetRequirement {
	var ingress filters.FlowSetRequirement
	if a.expIngress.None {
		return []filters.FlowSetRequirement{}
	}

	srcIP := a.src.Address()
	dstIP := a.dst.Address()
	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipResponse := filters.IP(dstIP, srcIP)
	ipRequest := filters.IP(srcIP, dstIP)

	tcpRequest := filters.TCP(0, a.dst.Port())
	tcpResponse := filters.TCP(a.dst.Port(), 0)
	if p.NodePort != 0 {
		tcpRequest = filters.Or(filters.TCP(0, p.NodePort), tcpRequest)
		tcpResponse = filters.Or(filters.TCP(p.NodePort, 0), tcpResponse)
	}

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if a.expIngress.Drop {
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
				Except: []filters.FlowRequirement{
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
		}
	case TCP:
		if a.expIngress.Drop {
			ingress = filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.Drop()), Msg: "Drop"},
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

var errNeedMoreFlows = errors.New("Required flows not found yet")

// ValidateFlows retrieves the flow pods of the specified pod and validates
// that all filters find a match. On failure, t.Fail() is called.
func (a *Action) ValidateFlows(ctx context.Context, pod, podIP string, reqs []filters.FlowSetRequirement) {
	hubbleClient := a.test.ctx.HubbleClient()
	if hubbleClient == nil {
		return
	}
	a.Logf("📄 Matching flows for pod %s", pod)

	w := utils.NewWaitObserver(ctx, utils.WaitParameters{
		Timeout:         defaults.FlowWaitTimeout,
		RetryInterval:   defaults.FlowRetryInterval,
		WarningInterval: defaults.FlowWaitTimeout / 2, // warn at least once during wait timeout
		Log: func(err error, wait string) {
			a.test.Logf("⌛ Waiting (%s) for flows: %s", wait, err)
		}})
	defer w.Cancel()

retry:
	since := a.flows[pod].lastTime()
	if since.IsZero() {
		since = a.started
	}
	flows, err := a.getFlows(ctx, hubbleClient, since, pod, podIP)
	if err != nil || len(flows) == 0 {
		if err == nil {
			err = fmt.Errorf("no flows returned")
		}
		if err := w.Retry(err); err != nil {
			a.Failf("Unable to retrieve flows of pod %q: %s", pod, err)
			return
		}
		goto retry
	}

	// append flows for the pod
	flows = a.flows[pod].append(flows)
	a.flows[pod] = flows

	res := FlowRequirementResults{FirstMatch: -1, LastMatch: -1}
	for i, req := range reqs {
		offset := 0
		var r FlowRequirementResults
		for offset < len(flows) {
			r = a.matchFlowRequirements(ctx, flows, offset, pod, &req)
			// Check if fully matched or no match for the first flow
			if !r.NeedMoreFlows || r.FirstMatch == -1 {
				break
			}
			// Try if some other flow instance would find both first and last required flows
			offset = r.FirstMatch + 1
		}
		if r.NeedMoreFlows {
			// Retry until timeout. On timeout, print the flows and
			// consider it a failure
			if err := w.Retry(errNeedMoreFlows); err == nil {
				goto retry
			}
		}
		// Merge results
		res.Merge(&r)
		a.Debugf("Merged flow validation results #%d: %v", i, res)
	}
	a.flowResults[pod] = res

	if !res.LastMatchTimestamp.IsZero() {
		a.test.ctx.StoreLastTimestamp(pod, res.LastMatchTimestamp)
	}

	if res.Failures == 0 {
		a.Logf("✅ Flow validation successful for pod %s (first: %d, last: %d, matched: %d)", pod, res.FirstMatch, res.LastMatch, len(res.Matched))
	} else {
		a.Failf("Flow validation failed for pod %s: %d failures (first: %d, last: %d, matched: %d)", pod, res.Failures, res.FirstMatch, res.LastMatch, len(res.Matched))
	}

	if res.Failures > 0 {
		a.failed = true
	}

	a.Log()
}

func (a *Action) getFlows(ctx context.Context, hubbleClient observer.ObserverClient, since time.Time, pod, podIP string) (flowsSet, error) {
	var set flowsSet

	if hubbleClient == nil {
		return set, nil
	}

	sinceTimestamp, err := ptypes.TimestampProto(since)
	if err != nil {
		return nil, fmt.Errorf("invalid since value %s: %s", since, err)
	}

	lastFlowTimestamp := a.test.ctx.LoadLastTimestamp(pod)
	if !lastFlowTimestamp.IsZero() && lastFlowTimestamp.After(since) {
		a.test.Logf("Using last flow timestamp: %s", lastFlowTimestamp)
		sinceTimestamp, err = ptypes.TimestampProto(lastFlowTimestamp)
		if err != nil {
			return nil, fmt.Errorf("invalid since value %s: %s", since, err)
		}
	}

	// The filter is liberal, it includes any flow that:
	// - source or destination IP matches pod IP
	// - source or destination pod name matches pod name
	filter := []*flow.FlowFilter{
		{SourceIp: []string{podIP}},
		{SourcePod: []string{pod}},
		{DestinationIp: []string{podIP}},
		{DestinationPod: []string{pod}},
	}

	request := &observer.GetFlowsRequest{
		Whitelist: filter,
		Since:     sinceTimestamp,
	}

	b, err := hubbleClient.GetFlows(ctx, request)
	if err != nil {
		return nil, err
	}

	for {
		res, err := b.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return set, nil
		case nil:
		default:
			if status.Code(err) == codes.Canceled {
				return set, nil
			}
			return nil, err
		}

		switch res.GetResponseTypes().(type) {
		case *observer.GetFlowsResponse_Flow:
			set = append(set, res)
		}

	}
}
