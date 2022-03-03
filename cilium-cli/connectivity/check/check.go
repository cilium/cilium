// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package check

import (
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/internal/k8s"
)

type Parameters struct {
	CiliumNamespace       string
	TestNamespace         string
	SingleNode            bool
	PrintFlows            bool
	ForceDeploy           bool
	Hubble                bool
	HubbleServer          string
	MultiCluster          string
	RunTests              []*regexp.Regexp
	SkipTests             []*regexp.Regexp
	PostTestSleepDuration time.Duration
	FlowValidation        string
	AllFlows              bool
	Writer                io.ReadWriter
	Verbose               bool
	Debug                 bool
	PauseOnFail           bool
	SkipIPCacheCheck      bool
	Perf                  bool
	PerfDuration          time.Duration
	PerfSamples           int
	CiliumBaseVersion     string
}

func (p Parameters) ciliumEndpointTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) podReadyTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) serviceReadyTimeout() time.Duration {
	return 30 * time.Second
}

func (p Parameters) ipCacheTimeout() time.Duration {
	return 20 * time.Second
}

func (p Parameters) validate() error {
	switch p.FlowValidation {
	case FlowValidationModeDisabled, FlowValidationModeWarning, FlowValidationModeStrict:
	default:
		return fmt.Errorf("invalid flow validation mode %q", p.FlowValidation)
	}

	return nil
}

// testEnabled returns true if the given test is allowed to run.
func (p Parameters) testEnabled(test string) bool {
	// Skip 'test' if any SkipTest matches.
	for _, re := range p.SkipTests {
		if re.MatchString(test) {
			return false
		}
	}
	// Run 'test' if any RunTest matches.
	for _, re := range p.RunTests {
		if re.MatchString(test) {
			return true
		}
	}

	// Enable test if there are no filters.
	return len(p.RunTests) == 0
}

type MatchMap map[int]bool

type FlowRequirementResults struct {
	FirstMatch         int
	LastMatch          int
	Matched            MatchMap
	Failures           int
	NeedMoreFlows      bool
	LastMatchTimestamp time.Time
}

func (r *FlowRequirementResults) Merge(from *FlowRequirementResults) {
	if r.FirstMatch < 0 || from.FirstMatch >= 0 && from.FirstMatch < r.FirstMatch {
		r.FirstMatch = from.FirstMatch
	}
	if from.FirstMatch > r.LastMatch {
		r.LastMatch = from.FirstMatch
	}
	if from.LastMatch > r.LastMatch {
		r.LastMatch = from.LastMatch
	}
	if r.Matched == nil {
		r.Matched = from.Matched
	} else {
		for k, v := range from.Matched {
			r.Matched[k] = v
		}
	}
	r.Failures += from.Failures
	r.NeedMoreFlows = r.NeedMoreFlows || from.NeedMoreFlows
	if from.LastMatchTimestamp.After(r.LastMatchTimestamp) {
		r.LastMatchTimestamp = from.LastMatchTimestamp
	}
}

// L4Protocol identifies the network protocol being tested
type L4Protocol int

const (
	TCP L4Protocol = iota
	UDP
	ICMP
)

// FlowParameters defines parameters for test result flow matching
type FlowParameters struct {
	// Protocol is the network protocol being tested
	Protocol L4Protocol

	// DNSRequired is true if DNS flows must be seen before the test protocol
	DNSRequired bool

	// RSTAllowed is true if TCP connection may end with either RST or FIN
	RSTAllowed bool

	// NodePort, if non-zero, indicates an alternative port number for the DstPort to be matched
	NodePort uint32
}

type flowsSet []*observer.GetFlowsResponse_Flow

func (f flowsSet) Contains(filter filters.FlowFilterImplementation, fc *filters.FlowContext) (int, bool, *flow.Flow) {
	if f == nil {
		return 0, false, nil
	}

	for i, res := range f {
		flow := res.Flow
		if filter.Match(flow, fc) {
			return i, true, flow
		}
	}

	return 0, false, nil
}

const (
	FlowValidationModeDisabled = "disabled"
	FlowValidationModeWarning  = "warning"
	FlowValidationModeStrict   = "strict"
)

type deploymentClients struct {
	src *k8s.Client
	dst *k8s.Client
}

func (d *deploymentClients) clients() []*k8s.Client {
	if d.src != d.dst {
		return []*k8s.Client{d.src, d.dst}
	}
	return []*k8s.Client{d.src}
}
