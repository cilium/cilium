// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/cilium/cilium-cli/connectivity/filters"
	"io"
	"regexp"
	"strings"

	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/sysdump"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/time"
)

type Parameters struct {
	AssumeCiliumVersion   string
	CiliumNamespace       string
	TestNamespace         string
	SingleNode            bool
	PrintFlows            bool
	ForceDeploy           bool
	Hubble                bool
	HubbleServer          string
	K8sLocalHostTest      bool
	MultiCluster          string
	RunTests              []*regexp.Regexp
	SkipTests             []*regexp.Regexp
	PostTestSleepDuration time.Duration
	FlowValidation        string
	AllFlows              bool
	Writer                io.ReadWriter
	Verbose               bool
	Debug                 bool
	Timestamp             bool
	PauseOnFail           bool
	SkipIPCacheCheck      bool
	// Perf is not user-facing parameter, but it's used to run perf subcommand
	// using connectivity test suite.
	Perf                  bool
	PerfReportDir         string
	PerfDuration          time.Duration
	PerfHostNet           bool
	PerfPodNet            bool
	PerfSamples           int
	CurlImage             string
	PerformanceImage      string
	JSONMockImage         string
	AgentDaemonSetName    string
	DNSTestServerImage    string
	IncludeUnsafeTests    bool
	AgentPodSelector      string
	CiliumPodSelector     string
	NodeSelector          map[string]string
	DeploymentAnnotations annotationsMap
	NamespaceAnnotations  annotations
	ExternalTarget        string
	ExternalCIDR          string
	ExternalIP            string
	ExternalOtherIP       string
	PodCIDRs              []podCIDRs
	NodeCIDRs             []string
	ControlPlaneCIDRs     []string
	K8sCIDR               string
	NodesWithoutCiliumIPs []nodesWithoutCiliumIP
	JunitFile             string
	JunitProperties       map[string]string

	IncludeConnDisruptTest        bool
	ConnDisruptTestSetup          bool
	ConnDisruptTestRestartsPath   string
	ConnDisruptTestXfrmErrorsPath string
	ConnDisruptDispatchInterval   time.Duration

	ExpectedDropReasons []string
	ExpectedXFRMErrors  []string

	FlushCT               bool
	SecondaryNetworkIface string

	K8sVersion           string
	HelmChartDirectory   string
	HelmValuesSecretName string

	Retry      uint
	RetryDelay time.Duration

	ConnectTimeout time.Duration
	RequestTimeout time.Duration
	CurlInsecure   bool

	CollectSysdumpOnFailure bool
	SysdumpOptions          sysdump.Options

	ExternalTargetCANamespace string
	ExternalTargetCAName      string

	Timeout time.Duration
}

type podCIDRs struct {
	CIDR   string
	HostIP string
}

type nodesWithoutCiliumIP struct {
	IP   string
	Mask int
}

type annotations map[string]string

func marshalMap[M ~map[K]V, K comparable, V any](m *M) string {
	if m == nil || len(*m) == 0 {
		return "{}" // avoids printing "null" for nil map
	}

	b, err := json.Marshal(*m)
	if err != nil {
		return fmt.Sprintf("error: %s", err)
	}
	return string(b)
}

// String implements pflag.Value
func (a *annotations) String() string {
	return marshalMap(a)
}

// Set implements pflag.Value
func (a *annotations) Set(s string) error {
	return json.Unmarshal([]byte(s), a)
}

// Type implements pflag.Value
func (a *annotations) Type() string {
	return "json"
}

type annotationsMap map[string]annotations

// String implements pflag.Value
func (a *annotationsMap) String() string {
	return marshalMap(a)
}

// Set implements pflag.Value
func (a *annotationsMap) Set(s string) error {
	var target annotationsMap
	err := json.Unmarshal([]byte(s), &target)
	if err != nil {
		return err
	} else if a == nil {
		return nil
	}

	// Validate keys for Match function, `*` is only allowed at the end of the string
	for key := range target {
		_, suffix, ok := strings.Cut(key, "*")
		if ok && len(suffix) > 0 {
			return fmt.Errorf("invalid match key %q: wildcard only allowed at end of key", key)
		}
	}

	*a = target
	return nil
}

// Type implements pflag.Value
func (a *annotationsMap) Type() string {
	return "json"
}

// Match extracts the annotations for the matching component s. If the
// annotation map contains s as a key, the corresponding value will be returned.
// Otherwise, every map key containing a `*` character will be treated as
// prefix pattern, i.e. a map key `foo*` will match the name `foobar`.
func (a *annotationsMap) Match(name string) annotations {
	// Invalid map or component name that contains a wildcard
	if a == nil || strings.Contains(name, "*") {
		return nil
	}

	// Direct match
	if match, ok := (*a)[name]; ok {
		return match
	}

	// Find the longest prefix match
	var longestPrefix string
	var longestMatch annotations
	for pattern, match := range *a {
		prefix, _, ok := strings.Cut(pattern, "*")
		if !ok || !strings.HasPrefix(name, prefix) {
			continue // not a matching pattern
		}

		if len(prefix) >= len(longestPrefix) {
			longestPrefix = prefix
			longestMatch = match
		}
	}

	return longestMatch
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

	// AltDstIP, if non-empty, indicates an alternative destination address
	// for the DstAddr to be matched. This is useful if the destination address
	// is NATed before Hubble can observe the packet, which for example is the
	// case with HostReachableServices
	AltDstIP string

	// AltDstPort, if non-zero, indicates an alternative port number for the
	// DstPort to be matched. This is useful if the destination port is NATed,
	// which is for example the case for service ports, NodePort or HostPort
	AltDstPort uint32
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
