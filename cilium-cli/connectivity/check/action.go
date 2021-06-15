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
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/api/v1/relay"
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

	// flowsMu protects flows.
	flowsMu sync.Mutex
	// flows is a map of all flow logs generated during the Action.
	flows flowsSet

	flowResults map[TestPeer]FlowRequirementResults

	// started is the timestamp the test started
	started time.Time

	// failed is true when Fail was called on the Action
	failed bool
}

func newAction(t *Test, name string, s Scenario, src *Pod, dst TestPeer) *Action {
	return &Action{
		name:        name,
		test:        t,
		scenario:    s,
		src:         src,
		dst:         dst,
		started:     time.Now(),
		flowResults: map[TestPeer]FlowRequirementResults{},
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

	// Emit unbuffered progress indicator.
	a.test.progress()

	// Only perform flow validation if a Hubble Relay connection is available.
	if a.test.ctx.params.Hubble {
		// Channel for the flow listener to notify us when ready.
		ready := make(chan bool, 1)

		// TODO(timo): Use an actual context that can be cancelled by the user.
		// `Run()` should take context.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start flow listener in the background.
		go func() {
			if err := a.followFlows(ctx, ready); err != nil {
				a.Fatalf("Receiving flows from Hubble Relay: %s", err)
			}
		}()

		// Wait for at least one Hubble node to signal that it's ready so we don't
		// generate any traffic before it can be captured.
		timeout := time.NewTimer(10 * time.Second)
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
	if a.test.ctx.PrintFlows() || a.failed {
		a.printFlows(a.Source())
		a.printFlows(a.Destination())
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

	stdout, stderr, err := pod.K8sClient.ExecInPodWithStderr(ctx,
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

func (a *Action) printFlows(peer TestPeer) {
	if len(a.flows) == 0 {
		a.Logf("📄 No flows recorded during action %s", a.name)
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

func (a *Action) matchFlowRequirements(ctx context.Context, flows flowsSet, offset int, req *filters.FlowSetRequirement) FlowRequirementResults {
	r := FlowRequirementResults{
		Matched:    MatchMap{},
		FirstMatch: -1,
		LastMatch:  -1,
	}

	// Skip 'offset' amount of flows.
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

	index, matched, _ := match(true, req.First, &flowCtx)
	if !matched {
		r.NeedMoreFlows = true
		// No point trying to match more if First does not match.
		return r
	}

	r.FirstMatch = offset + index

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

	return r
}

func (a *Action) GetEgressRequirements(p FlowParameters) (reqs []filters.FlowSetRequirement) {
	var egress filters.FlowSetRequirement
	srcIP := a.src.Address()
	dstIP := a.dst.Address()

	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipRequest := filters.IP(srcIP, dstIP)
	ipResponse := filters.IP(dstIP, srcIP)

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
				code := uint32(math.MaxUint32)
				if s, err := strconv.Atoi(a.expEgress.HTTP.Status); err == nil {
					code = uint32(s)
				}
				egress.Middle = append(egress.Middle, filters.FlowRequirement{Filter: filters.HTTP(code, a.expEgress.HTTP.Method, a.expEgress.HTTP.URL), Msg: "HTTP"})
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
		// Override to allow for any DNS server
		ipRequest := filters.IP(srcIP, "")
		ipResponse := filters.IP("", srcIP)

		dnsRequest := filters.Or(filters.UDP(0, 53), filters.TCP(0, 53))
		dnsResponse := filters.Or(filters.UDP(53, 0), filters.TCP(53, 0))

		dns := filters.FlowSetRequirement{First: filters.FlowRequirement{Filter: filters.And(ipRequest, dnsRequest), Msg: "DNS request"}}
		if a.expEgress.DNSProxy {
			qname := a.dst.Address() + "."
			dns.Middle = []filters.FlowRequirement{{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"}}
			dns.Last = filters.FlowRequirement{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(qname, 0)), Msg: "DNS proxy"}
			// 5 is the default rcode returned on error such as policy deny
			dns.Except = []filters.FlowRequirement{{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(qname, 5)), Msg: "DNS proxy DROP"}}
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
					{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
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

// waitForRelay polls the server status from Relay until either it's connected to all the Hubble
// instances (success) or the context is cancelled (failure).
func (a *Action) waitForRelay(ctx context.Context, client observer.ObserverClient) error {
	for {
		res, err := client.ServerStatus(ctx, &observer.ServerStatusRequest{})
		if err == nil && (res.NumUnavailableNodes == nil || res.NumUnavailableNodes.Value == 0) {
			// This means all the nodes are available.
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("hubble server status failure: %w", ctx.Err())
		case <-time.After(time.Second):
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
	filter := []*flow.FlowFilter{
		{SourcePod: []string{pod.Name()}},
		{DestinationPod: []string{pod.Name()}},
	}

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
				return nil
			}

			// Return gracefully on 'canceled' gRPC error.
			if status.Code(err) == codes.Canceled {
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
func (a *Action) matchAllFlowRequirements(ctx context.Context, reqs []filters.FlowSetRequirement) FlowRequirementResults {
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

	for _, req := range reqs {
		res := a.matchFlowRequirements(ctx, a.flows, 0, &req)
		if res.NeedMoreFlows || res.FirstMatch == -1 {
			break
		}

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

	// There can be am empty list of flow requirements for some tests, in which
	// case we should not perform validation.
	if len(reqs) == 0 {
		a.Debugf("No flow requirements to validate for peer %s", peer.Name())
		return
	}

	a.Logf("📄 Validating flows for peer %s", peer.Name())

	var res FlowRequirementResults

	interval := time.NewTicker(defaults.FlowRetryInterval)
	defer interval.Stop()

	ctx, cancel := context.WithTimeout(ctx, defaults.FlowWaitTimeout)
	defer cancel()

r:
	for {
		select {
		// Attempt to validate all flows received during the Action so far,
		// once per validation interval.
		case <-interval.C:
			a.Debugf("Validating %d flows against %d requirements", len(a.flows), len(reqs))

			res = a.matchAllFlowRequirements(ctx, reqs)
			if !res.NeedMoreFlows && res.FirstMatch != -1 {
				// TODO(timo): This success condition should be a method on FlowRequirementResults.
				break r
			}
		case <-ctx.Done():
			a.Fail("Aborting flow matching:", ctx.Err())
			break r
		}
	}

	// Store the validation result for the given peer.
	a.flowResults[peer] = res

	if res.Failures == 0 && res.FirstMatch >= 0 {
		a.Logf("✅ Flow validation successful for peer %s (first: %d, last: %d, matched: %d)", peer.Name(), res.FirstMatch, res.LastMatch, len(res.Matched))
	} else {
		a.Failf("Flow validation failed for peer %s: %d failures (first: %d, last: %d, matched: %d)", peer.Name(), res.Failures, res.FirstMatch, res.LastMatch, len(res.Matched))
	}

	a.Log()
}
