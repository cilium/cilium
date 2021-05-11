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
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/internal/k8s"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
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

func (p Parameters) validate() error {
	switch p.FlowValidation {
	case FlowValidationModeDisabled, FlowValidationModeWarning, FlowValidationModeStrict:
	default:
		return fmt.Errorf("invalid flow validation mode %q", p.FlowValidation)
	}

	return nil
}

func (p Parameters) testEnabled(test string) bool {
	// Skip 'test' if any SkipTest matches
	for _, re := range p.SkipTests {
		if re.MatchString(test) {
			return false
		}
	}
	// Run 'test' if any RunTest matches
	for _, re := range p.RunTests {
		if re.MatchString(test) {
			return true
		}
	}
	// Else run if tests are not limited
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

type flowsSet []*observer.GetFlowsResponse

func (f flowsSet) Contains(filter filters.FlowFilterImplementation) (int, bool, *flow.Flow) {
	if f == nil {
		return 0, false, nil
	}

	for i, res := range f {
		flow := res.GetFlow()
		if filter.Match(flow) {
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
