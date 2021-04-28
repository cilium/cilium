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
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	hubprinter "github.com/cilium/hubble/pkg/printer"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	ClientDeploymentName  = "client"
	Client2DeploymentName = "client2"

	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
)

var serviceLabels = map[string]string{
	"kind": kindEchoName,
}

func newService(name string, selector map[string]string, labels map[string]string, portName string, port int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{Name: name, Port: int32(port)},
			},
			Selector: selector,
		},
	}
}

type deploymentParameters struct {
	Name           string
	Kind           string
	Image          string
	Replicas       int
	Port           int
	Command        []string
	Affinity       *corev1.Affinity
	ReadinessProbe *corev1.Probe
	Labels         map[string]string
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	replicas32 := int32(p.Replicas)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
			Labels: map[string]string{
				"name": p.Name,
				"kind": p.Kind,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: p.Name,
					Labels: map[string]string{
						"name": p.Name,
						"kind": p.Kind,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: p.Name,
							Env: []corev1.EnvVar{
								{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
							},
							Ports: []corev1.ContainerPort{
								{ContainerPort: int32(p.Port)},
							},
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							ReadinessProbe:  p.ReadinessProbe,
						},
					},
					Affinity: p.Affinity,
				},
			},
			Replicas: &replicas32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": p.Name,
					"kind": p.Kind,
				},
			},
		},
	}

	for k, v := range p.Labels {
		dep.Spec.Template.ObjectMeta.Labels[k] = v
	}

	return dep
}

func newLocalReadinessProbe(port int, path string) *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   path,
				Port:   intstr.FromInt(port),
				Scheme: corev1.URISchemeHTTP,
			},
		},
		TimeoutSeconds:      int32(2),
		SuccessThreshold:    int32(1),
		PeriodSeconds:       int32(1),
		InitialDelaySeconds: int32(1),
		FailureThreshold:    int32(3),
	}
}

type k8sPolicyImplementation interface {
	ListCiliumNetworkPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumNetworkPolicyList, error)
	GetCiliumNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*ciliumv2.CiliumNetworkPolicy, error)
	CreateCiliumNetworkPolicy(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy, opts metav1.CreateOptions) (*ciliumv2.CiliumNetworkPolicy, error)
	UpdateCiliumNetworkPolicy(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy, opts metav1.UpdateOptions) (*ciliumv2.CiliumNetworkPolicy, error)
	DeleteCiliumNetworkPolicy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
}

type k8sConnectivityImplementation interface {
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	GetService(ctx context.Context, namespace, service string, opts metav1.GetOptions) (*corev1.Service, error)
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	DeploymentIsReady(ctx context.Context, namespace, deployment string) error
	DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error
	CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	ListServices(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.ServiceList, error)
	ListCiliumExternalWorkloads(ctx context.Context, options metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	GetCiliumEndpoint(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*ciliumv2.CiliumEndpoint, error)
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
	ClusterName() (name string)

	CiliumLogs(ctx context.Context, namespace, pod string, since time.Time, filter *regexp.Regexp) (string, error)

	k8sPolicyImplementation
}

// PodContext is a pod acting as a peer in a connectivity test
type PodContext struct {
	// K8sClient is the Kubernetes client of the cluster this pod is
	// running in
	K8sClient k8sConnectivityImplementation

	// Pod is the Kubernetes Pod resource
	Pod *corev1.Pod
}

// Name returns the absolute name of the pod
func (p PodContext) Name() string {
	return p.Pod.Namespace + "/" + p.Pod.Name
}

// Address returns the network address of the pod
func (p PodContext) Address() string {
	return p.Pod.Status.PodIP
}

// HasLabel checks if given label exists and value matches
func (p PodContext) HasLabel(name, value string) bool {
	v, ok := p.Pod.Labels[name]
	return ok && v == value
}

// ServiceContext is a service acting as a peer in a connectivity test
type ServiceContext struct {
	// Service is the Kubernetes service resource
	Service *corev1.Service
}

// Name returns the absolute name of the service
func (s ServiceContext) Name() string {
	return s.Service.Namespace + "/" + s.Service.Name
}

// Address returns the network address of the service
func (s ServiceContext) Address() string {
	return s.Service.Name
}

// HasLabel checks if given label exists and value matches
func (s ServiceContext) HasLabel(name, value string) bool {
	v, ok := s.Service.Labels[name]
	return ok && v == value
}

// NetworkEndpointContext is a network endpoint acting as a peer in a connectivity test
type NetworkEndpointContext struct {
	CustomName string

	// Peer is the network address
	Peer string
}

// Name is the absolute name of the network endpoint
func (n NetworkEndpointContext) Name() string {
	if n.CustomName != "" {
		return n.CustomName
	}

	return n.Peer
}

// Address returns the network address of the network endpoint.
func (n NetworkEndpointContext) Address() string {
	return n.Peer
}

// HasLabel checks if given label exists and value matches
func (n NetworkEndpointContext) HasLabel(name, value string) bool {
	return false
}

// ExternalWorkloadContext is an external workload acting as a peer in a
// connectivity test.
type ExternalWorkloadContext struct {
	// ExternalWorkload is the Kubernetes Cilium external workload resource
	ExternalWorkload *ciliumv2.CiliumExternalWorkload
}

// Name returns the name of the external workload.
func (e ExternalWorkloadContext) Name() string {
	return e.ExternalWorkload.Name
}

// Address returns the network address of the external workload.
func (e ExternalWorkloadContext) Address() string {
	return e.ExternalWorkload.Status.IP
}

// HasLabel checks if given label exists and value matches
func (e ExternalWorkloadContext) HasLabel(name, value string) bool {
	v, ok := e.ExternalWorkload.Labels[name]
	return ok && v == value
}

// TestContext is the context a test uses to interact with the test framework
type TestContext interface {
	// EchoPods returns a map of all deployed echo pods
	EchoPods() map[string]PodContext

	// ClientPods returns a map of all deployed client pods
	ClientPods() map[string]PodContext

	// RandomClientPod returns a randomly selected client pod, if available
	RandomClientPod() *PodContext

	// EchoServices returns a map of all deployed echo services
	EchoServices() map[string]ServiceContext

	// ExternalWorkloads returns a map of all deployed external workloads
	ExternalWorkloads() map[string]ExternalWorkloadContext

	// ApplyCNPs applies the given CNP to the test context, returns the number of failures
	ApplyCNPs(ctx context.Context, deletePrevious bool, cnps []*ciliumv2.CiliumNetworkPolicy) int

	// DeleteCNP deleted the given CNP from the test context
	DeleteCNPs(ctx context.Context, cnps []*ciliumv2.CiliumNetworkPolicy)

	// Log is used to log a status update
	Log(format string, a ...interface{})

	// Header logs a header to segment tests
	Header(format string, a ...interface{})

	// HubbleClient returns the Hubble client to retrieve flow logs
	HubbleClient() observer.ObserverClient

	// PrintFlows returns true if flow logs should be printed
	PrintFlows() bool

	// AllFlows returns true if all flows should be shown
	AllFlows() bool

	// Verbose returns true if additional diagnostic messages should be shown
	Verbose() bool

	// SetVerbose sets verbosity value
	SetVerbose(bool)

	// ResetVerbose returns the normal verbosity value
	ResetVerbose()

	// FlowAggregation returns true if flow aggregation is enabled in any
	// of the clusters
	FlowAggregation() bool

	// PostTestSleepDuration is the duration to sleep after each test
	PostTestSleepDuration() time.Duration

	// Report is called to report the outcome of a test
	Report(r TestResult)

	// StoreLastTimestamp stores the last flow timestamp of a test run to
	// allow later tests to skip flows up to this point
	StoreLastTimestamp(pod string, t time.Time)

	// LoadLastTimestamp loads the last flow timestamp of a previous test for a particular pod
	LoadLastTimestamp(pod string) time.Time
}

// TestRun is the state of an individual test run
type TestRun struct {
	// name is the name of the test being run
	name string

	// verboseName is the name of the test including the name of the peers
	verboseName string

	// context is the test context of the framework
	context TestContext

	// Src is the peer used as the source (client)
	Src TestPeer

	// Dst is the peer used as the destination (server)
	Dst TestPeer

	// DstPort is the destination port number used by the traffic in this test case
	DstPort int

	// expectedEgress is the expected test result for egress from the source pod
	expectedEgress Result

	// expectedIngress is the expected test result for the ingress in to the destination pod
	expectedIngress Result

	// flows is a map of all flow logs, indexed by pod name
	flows map[string]*flowsSet

	flowResults map[string]FlowRequirementResults

	// started is the timestamp the test started
	started time.Time

	// failures is the number of failures encountered in this test run
	failures int

	// warnings is the number of warnings encountered in this test run
	warnings int
}

// NewTestRun creates a new test run
func NewTestRun(t ConnectivityTest, c TestContext, src, dst TestPeer, dstPort int) *TestRun {
	c.ResetVerbose()
	c.Header("🔌 [%s] Testing %s -> %s:%d...", t.Name(), src.Name(), dst.Name(), dstPort)

	run := &TestRun{
		name:        t.Name(),
		verboseName: fmt.Sprintf("%s: %s -> %s:%d", t.Name(), src.Name(), dst.Name(), dstPort),
		context:     c,
		Src:         src,
		Dst:         dst,
		DstPort:     dstPort,
		started:     time.Now(),
		flows:       map[string]*flowsSet{},
		flowResults: map[string]FlowRequirementResults{},
	}

	// Record policy apply failure on each test run
	k := c.(*K8sConnectivityCheck)
	if k.policyFailures > 0 {
		run.Failure("Policy apply failed")
	}

	// Set policy expectations for this test run
	run.expectedEgress, run.expectedIngress = t.getExpectations(run)

	return run
}

// Failure must be called when a failure is detected performing the test
func (t *TestRun) Failure(format string, a ...interface{}) {
	t.context.Log("❌ "+format, a...)
	t.failures++
	t.context.SetVerbose(true)
}

// Success can be called to log a successful event
func (t *TestRun) Success(format string, a ...interface{}) {
	t.context.Log("✅ "+format, a...)
}

// Waiting can be called to log a slow event
func (t *TestRun) Waiting(format string, a ...interface{}) {
	t.context.Log("⌛ "+format+"...", a...)
}

// LogResult can be called to log command results
func (t *TestRun) LogResult(cmd []string, err error, stdout, stderr bytes.Buffer) {
	cmdName := cmd[0]
	cmdStr := strings.Join(cmd, " ")
	shouldSucceed := !t.expectedEgress.Drop && !t.expectedIngress.Drop
	if err != nil || stderr.Len() > 0 {
		if shouldSucceed {
			t.Failure("%s command %q failed: %s", cmdName, cmdStr, err)
		} else {
			t.Success("%s command %q failed as expected: %s", cmdName, cmdStr, err)
		}
	} else {
		if shouldSucceed {
			t.Success("%s command %q succeeded", cmdName, cmdStr)
		} else {
			t.Failure("%s command %q succeeded while it should have failed", cmdName, cmdStr)
		}
	}
	if t.context.Verbose() {
		if stderr.Len() > 0 {
			t.context.Log("ℹ️  %s error: %s", cmdName, stderr.String())
		} else if stdout.Len() > 0 {
			t.context.Log("ℹ️  %s output: %s", cmdName, stdout.String())
		}
	}
}

// Warning must be called when a warning is detected performing the test
func (t *TestRun) Warning(format string, a ...interface{}) {
	t.context.Log("⚠️  "+format, a...)
	t.warnings++
}

func (t *TestRun) printFlows(pod string, f *flowsSet, r FlowRequirementResults) {
	if f == nil {
		t.context.Log("📄 No flows recorded for pod %s", pod)
		return
	}

	t.context.Log("📄 Flow logs of pod %s:", pod)
	printer := hubprinter.New(hubprinter.Compact(), hubprinter.WithIPTranslation())
	defer printer.Close()
	for index, flow := range f.flows {
		if !t.context.AllFlows() && r.FirstMatch > 0 && r.FirstMatch > index {
			continue
		}

		if !t.context.AllFlows() && r.LastMatch > 0 && r.LastMatch < index {
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

		//lint:ignore SA1019 Summary is deprecated but there is no real alternative yet
		t.context.Log("%s%s: %s -> %s %s %s (%s)", flowPrefix, ts, src, dst, hubprinter.GetFlowType(f), f.Verdict.String(), f.Summary)
	}
}

type MatchMap map[int]bool

type FlowRequirementResults struct {
	FirstMatch         int
	LastMatch          int
	Matched            MatchMap
	Log                []string
	Failures           int
	NeedMoreFlows      bool
	LastMatchTimestamp time.Time
}

func (t *TestRun) matchFlowRequirements(ctx context.Context, flows *flowsSet, pod string, req *filters.FlowSetRequirement) (r FlowRequirementResults) {
	var goodLog []string

	r.Matched = MatchMap{}

	match := func(expect bool, f filters.FlowRequirement) (int, bool, *flow.Flow) {
		index, match, flow := flows.Contains(f.Filter)

		if match {
			r.Matched[index] = expect
		}

		if match != expect {
			// Unless we show all flows, good flows are only shown on failure
			if !t.context.AllFlows() {
				r.Log = append(r.Log, goodLog...)
				goodLog = []string{}
			}

			msgSuffix := "not found"
			if !expect {
				msgSuffix = "found"
			}

			r.Log = append(r.Log, fmt.Sprintf("❌ %s %s %s for pod %s", f.Msg, f.Filter.String(), msgSuffix, pod))
			r.Failures++
		} else {
			msgSuffix := "found"
			if !expect {
				msgSuffix = "not found"
			}

			entry := "✅ " + fmt.Sprintf("%s %s for pod %s", f.Msg, msgSuffix, pod)
			// Either show all flows or collect them so we can attach on failure
			if t.context.AllFlows() {
				r.Log = append(r.Log, entry)
			} else {
				goodLog = append(goodLog, entry)
			}
		}

		return index, expect, flow
	}

	if index, match, _ := match(true, req.First); !match {
		r.NeedMoreFlows = true
	} else {
		r.FirstMatch = index
	}

	for _, f := range req.Middle {
		if f.SkipOnAggregation && t.context.FlowAggregation() {
			continue
		}
		match(true, f)
	}

	if !(req.Last.SkipOnAggregation && t.context.FlowAggregation()) {
		if index, match, lastFlow := match(true, req.Last); !match {
			r.NeedMoreFlows = true
		} else {
			r.LastMatch = index

			if lastFlow != nil {
				flowTimestamp, err := ptypes.Timestamp(lastFlow.Time)
				if err == nil {
					r.LastMatchTimestamp = flowTimestamp
				}
			}
		}
	}

	for _, f := range req.Except {
		match(false, f)
	}

	return
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
	NodePort int
}

func (t *TestRun) GetEgressRequirements(p FlowParameters) *filters.FlowSetRequirement {
	var egress *filters.FlowSetRequirement
	srcIP := t.Src.Address()
	dstIP := t.Dst.Address()

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

		if t.expectedEgress.Drop {
			egress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			if t.expectedIngress.Drop {
				// If ingress drops is in the same node we get the drop flows also for egress, tolerate that
				egress = &filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last:  filters.FlowRequirement{Filter: filters.Or(filters.And(ipResponse, icmpResponse), filters.And(ipRequest, filters.Drop())), Msg: "ICMP response or request drop", SkipOnAggregation: true},
				}
			} else {
				egress = &filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
					Except: []filters.FlowRequirement{
						{Filter: filters.Drop(), Msg: "Drop"},
					},
				}
			}
		}
	case TCP:
		tcpRequest := filters.TCP(0, t.DstPort)
		tcpResponse := filters.TCP(t.DstPort, 0)
		if p.NodePort != 0 {
			tcpRequest = filters.Or(filters.TCP(0, p.NodePort), tcpRequest)
			tcpResponse = filters.Or(filters.TCP(p.NodePort, 0), tcpResponse)
		}

		if t.expectedEgress.Drop {
			egress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.SYNACK(), Msg: "SYN-ACK"},
					{Filter: filters.FIN(), Msg: "FIN"},
				},
			}
		} else {
			egress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Middle: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK", SkipOnAggregation: true},
				},
				// Either side may FIN first
				Last: filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				Except: []filters.FlowRequirement{
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
			if t.expectedEgress.HTTP.Status != "" || t.expectedEgress.HTTP.Method != "" || t.expectedEgress.HTTP.URL != "" {
				code, err := strconv.Atoi(t.expectedEgress.HTTP.Status)
				if err != nil {
					code = math.MaxUint32
				}
				egress.Middle = append(egress.Middle, filters.FlowRequirement{Filter: filters.HTTP(uint32(code), t.expectedEgress.HTTP.Method, t.expectedEgress.HTTP.URL), Msg: "HTTP"})
			}
			if p.RSTAllowed {
				// For the connection termination, we will either see:
				// a) FIN + FIN b) FIN + RST c) RST
				// Either side may RST or FIN first
				egress.Last = filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Or(filters.FIN(), filters.RST())), Msg: "FIN or RST", SkipOnAggregation: true}
			} else {
				egress.Except = append(egress.Except, filters.FlowRequirement{Filter: filters.RST(), Msg: "RST"})
			}
		}
	case UDP:
		t.Failure("UDP egress flow matching not implemented yet")
	default:
		t.Failure("Invalid egress flow matching protocol %d", p.Protocol)
	}

	if p.DNSRequired || t.expectedEgress.DNSProxy {
		dnsRequest := filters.Or(filters.UDP(0, 53), filters.TCP(0, 53))
		dnsResponse := filters.Or(filters.UDP(53, 0), filters.TCP(53, 0))

		first := egress.First
		egress.First = filters.FlowRequirement{Filter: filters.And(ipRequest, dnsRequest), Msg: "DNS request"}
		egress.Middle = append([]filters.FlowRequirement{
			{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"},
			first,
		}, egress.Middle...)

		if t.expectedEgress.DNSProxy {
			egress.Middle = append([]filters.FlowRequirement{
				{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(t.Dst.Address()+".", 0)), Msg: "DNS proxy"},
			}, egress.Middle...)
		}
	}

	return egress
}

func (t *TestRun) GetIngressRequirements(p FlowParameters) *filters.FlowSetRequirement {
	var ingress *filters.FlowSetRequirement
	if t.expectedIngress.None {
		return ingress
	}

	srcIP := t.Src.Address()
	dstIP := t.Dst.Address()
	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipResponse := filters.IP(dstIP, srcIP)
	ipRequest := filters.IP(srcIP, dstIP)

	tcpRequest := filters.TCP(0, t.DstPort)
	tcpResponse := filters.TCP(t.DstPort, 0)
	if p.NodePort != 0 {
		tcpRequest = filters.Or(filters.TCP(0, p.NodePort), tcpRequest)
		tcpResponse = filters.Or(filters.TCP(p.NodePort, 0), tcpResponse)
	}

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if t.expectedIngress.Drop {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
				Except: []filters.FlowRequirement{
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
		}
	case TCP:
		if t.expectedIngress.Drop {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
					{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				},
			}
		} else {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Middle: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
				},
				// Either side may FIN first
				Last: filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				Except: []filters.FlowRequirement{
					{Filter: filters.RST(), Msg: "RST"},
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
		}
	case UDP:
		t.Failure("UDP ingress flow matching not implemented yet")
	default:
		t.Failure("Invalid ingress flow matching protocol %d", p.Protocol)
	}

	return ingress
}

// ValidateFlows retrieves the flow pods of the specified pod and validates
// that all filters find a match. On failure, t.Failure() is called.
func (t *TestRun) ValidateFlows(ctx context.Context, pod, podIP string, req *filters.FlowSetRequirement) {
	hubbleClient := t.context.HubbleClient()
	if hubbleClient == nil {
		return
	}

	w := utils.NewWaitObserver(ctx, utils.WaitParameters{
		Timeout:       defaults.FlowWaitTimeout,
		RetryInterval: defaults.FlowRetryInterval,
		Log: func(err error, wait string) {
			t.context.Log("⌛ Waiting (%s) for flows: %s", wait, err)
		}})
	defer w.Cancel()

retry:
	flows, err := t.getFlows(ctx, hubbleClient, t.started, pod, podIP)
	if err != nil || flows == nil || len(flows.flows) == 0 {
		if err == nil {
			err = fmt.Errorf("no flows returned")
		}
		if err := w.Retry(err); err != nil {
			t.Failure("Unable to retrieve flows of pod %q: %s", pod, err)
			return
		}
		goto retry
	}

	r := t.matchFlowRequirements(ctx, flows, pod, req)
	if r.NeedMoreFlows {
		// Retry until timeout. On timeout, print the flows and
		// consider it a failure
		if err := w.Retry(err); err != nil {
			goto retry
		}
	}

	t.flows[pod] = flows
	t.flowResults[pod] = r

	if !r.LastMatchTimestamp.IsZero() {
		t.context.StoreLastTimestamp(pod, r.LastMatchTimestamp)
	}

	if r.Failures == 0 {
		t.context.Log("✅ Flow validation successful for pod %s (first: %d, last: %d, matched: %d, nlog: %d)", pod, r.FirstMatch, r.LastMatch, len(r.Matched), len(r.Log))
	} else {
		t.context.Log("❌ Flow validation failed for pod %s: %d failures (first: %d, last: %d, matched: %d, nlog: %d)", pod, r.Failures, r.FirstMatch, r.LastMatch, len(r.Matched), len(r.Log))
	}

	for _, p := range r.Log {
		t.context.Log(p)
	}

	if r.Failures > 0 {
		t.failures++
	}
}

// End is called at the end of a test run to signal completion. It must be
// called for both successful and failed test runs. It will log a summary and
// print flow logs if necessary.
func (t *TestRun) End() {
	if t.context.PrintFlows() || t.failures > 0 || t.warnings > 0 {
		for name, flows := range t.flows {
			t.printFlows(name, flows, t.flowResults[name])
		}
	}

	prefix := "✅"
	if t.failures > 0 {
		prefix = "❌"
	} else if t.warnings > 0 {
		prefix = "⚠️ "
	}

	t.context.Log("%s [%s] %s (%s) -> %s (%s)",
		prefix, t.name,
		t.Src.Name(), t.Src.Address(),
		t.Dst.Name(), t.Dst.Address())

	if duration := t.context.PostTestSleepDuration(); duration != time.Duration(0) {
		time.Sleep(duration)
	}

	t.context.Report(TestResult{
		Name:     t.verboseName,
		Failures: t.failures,
		Warnings: t.warnings,
	})
}

// TestPeer is the abstraction used for all peer types (pods, services, IPs,
// DNS names) used for connectivity testing
type TestPeer interface {
	// Name must return the absolute name of the peer
	Name() string

	// Address must return the network address of the peer. This can be a
	// DNS name or an IP address.
	Address() string

	// HasLabel checks if given label exists and value matches
	HasLabel(name, value string) bool
}

// ConnectivityTest is the interface to implement for all connectivity tests
type ConnectivityTest interface {
	Policy

	// Name must return the name of the test
	Name() string

	// PolicyOnly returns true if there is policy setup but no traffic scenario with this test
	PolicyOnly() bool

	// Run is called to run the connectivity test
	Run(ctx context.Context, c TestContext)
}

type TestResult struct {
	Name     string
	Failures int
	Warnings int
}

func (t TestResult) String() string {
	switch {
	case t.Failures > 0:
		return "❌ " + t.Name
	case t.Warnings > 0:
		return "⚠️  " + t.Name
	default:
		return "✅ " + t.Name
	}
}

type TestResults map[string]TestResult

func (t TestResults) Warnings() (warnings int) {
	for _, result := range t {
		if result.Warnings > 0 {
			warnings++
		}
	}
	return
}

func (t TestResults) Failed() (failed int) {
	for _, result := range t {
		if result.Failures > 0 {
			failed++
		}
	}
	return
}

type K8sConnectivityCheck struct {
	client             k8sConnectivityImplementation
	ciliumNamespace    string
	hubbleClient       observer.ObserverClient
	params             Parameters
	clients            *deploymentClients
	ciliumPods         map[string]PodContext
	echoPods           map[string]PodContext
	clientPods         map[string]PodContext
	echoServices       map[string]ServiceContext
	externalWorkloads  map[string]ExternalWorkloadContext
	results            TestResults
	lastFlowTimestamps map[string]time.Time
	flowAggregation    bool
	policies           map[string]*ciliumv2.CiliumNetworkPolicy
	policyFailures     int
	verbose            bool
}

func NewK8sConnectivityCheck(client k8sConnectivityImplementation, p Parameters) (*K8sConnectivityCheck, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	k := &K8sConnectivityCheck{
		client:             client,
		ciliumNamespace:    "kube-system",
		params:             p,
		lastFlowTimestamps: map[string]time.Time{},
	}

	return k, nil
}

func (k *K8sConnectivityCheck) enableHubbleClient(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := grpc.DialContext(dialCtx, k.params.HubbleServer, grpc.WithInsecure())
	if err != nil {
		return err
	}

	k.hubbleClient = observer.NewObserverClient(c)

	status, err := k.hubbleClient.ServerStatus(ctx, &observer.ServerStatusRequest{})
	if err != nil {
		k.Log("⚠️  Unable to contact Hubble Relay: %s", err)
		k.Log("⚠️  Did you enable and expose Hubble + Relay?")
		k.Log("ℹ️  You can export Relay with a port-forward: kubectl port-forward -n kube-system deployment/hubble-relay 4245:4245")
		k.Log("ℹ️  Disabling Hubble telescope and flow validation...")
		k.hubbleClient = nil
		k.params.Hubble = false

		if k.params.FlowValidation == FlowValidationModeStrict {
			k.Log("❌ In --flow-validation=strict mode, Hubble must be available to validate flows")
			return fmt.Errorf("hubble is not available: %w", err)
		}
	} else {
		k.Log("ℹ️  Hubble is OK, flows: %d/%d", status.NumFlows, status.MaxFlows)
	}

	return nil
}

type flowsSet struct {
	flows []*observer.GetFlowsResponse
}

func (t *TestRun) getFlows(ctx context.Context, hubbleClient observer.ObserverClient, since time.Time, pod, podIP string) (*flowsSet, error) {
	set := &flowsSet{}

	if hubbleClient == nil {
		return set, nil
	}

	sinceTimestamp, err := ptypes.TimestampProto(since)
	if err != nil {
		return nil, fmt.Errorf("invalid since value %s: %s", since, err)
	}

	lastFlowTimestamp := t.context.LoadLastTimestamp(pod)
	if !lastFlowTimestamp.IsZero() && lastFlowTimestamp.After(since) {
		t.context.Log("Using last flow timestamp: %s", lastFlowTimestamp)
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
			set.flows = append(set.flows, res)
		}

	}
}

func (f *flowsSet) Contains(filter filters.FlowFilterImplementation) (int, bool, *flow.Flow) {
	if f == nil {
		return 0, false, nil
	}

	for i, res := range f.flows {
		flow := res.GetFlow()
		if filter.Match(flow) {
			return i, true, flow
		}
	}

	return 0, false, nil
}

func (k *K8sConnectivityCheck) Print(pod string, f *flowsSet) {
	if f == nil {
		k.Log("📄 No flows recorded for pod %s", pod)
		return
	}

	k.Log("📄 Flow logs of pod %s:", pod)
	printer := hubprinter.New(hubprinter.Compact(), hubprinter.WithIPTranslation())
	defer printer.Close()
	for _, flow := range f.flows {
		if err := printer.WriteProtoFlow(flow); err != nil {
			k.Log("Unable to print flow: %s", err)
		}
	}
}

const (
	FlowValidationModeDisabled = "disabled"
	FlowValidationModeWarning  = "warning"
	FlowValidationModeStrict   = "strict"
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
	Writer                io.Writer
	Verbose               bool
}

func (p Parameters) ciliumEndpointTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) podReadyTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) serviceReadyTimeout() time.Duration {
	return 5 * time.Minute
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

func (k *K8sConnectivityCheck) deleteDeployments(ctx context.Context, client k8sConnectivityImplementation) error {
	k.Log("🔥 [%s] Deleting connectivity check deployments...", client.ClusterName())
	client.DeleteDeployment(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteDeployment(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteDeployment(ctx, k.params.TestNamespace, ClientDeploymentName, metav1.DeleteOptions{})
	client.DeleteDeployment(ctx, k.params.TestNamespace, Client2DeploymentName, metav1.DeleteOptions{})
	client.DeleteService(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteService(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteNamespace(ctx, k.params.TestNamespace, metav1.DeleteOptions{})

	_, err := client.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
	if err == nil {
		k.Log("⌛ [%s] Waiting for namespace %s to disappear", client.ClusterName(), k.params.TestNamespace)
		for err == nil {
			time.Sleep(time.Second)
			_, err = client.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
		}
	}

	return nil
}

func (k *K8sConnectivityCheck) deploymentList() (srcList []string, dstList []string) {
	srcList = []string{ClientDeploymentName, Client2DeploymentName, echoSameNodeDeploymentName}

	if k.params.MultiCluster != "" || !k.params.SingleNode {
		dstList = append(dstList, echoOtherNodeDeploymentName)
	}

	return srcList, dstList
}

type deploymentClients struct {
	src k8sConnectivityImplementation
	dst k8sConnectivityImplementation
}

// clients return a slice of unique k8s clients to use
func (d *deploymentClients) clients() []k8sConnectivityImplementation {
	if d.src != d.dst {
		return []k8sConnectivityImplementation{d.src, d.dst}
	}
	return []k8sConnectivityImplementation{d.src}
}

func (k *K8sConnectivityCheck) logAggregationMode(ctx context.Context, client k8sConnectivityImplementation) (string, error) {
	cm, err := client.GetConfigMap(ctx, k.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data == nil {
		return "", fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	return cm.Data[defaults.ConfigMapKeyMonitorAggregation], nil
}

func (k *K8sConnectivityCheck) initClients(ctx context.Context) (*deploymentClients, error) {
	c := &deploymentClients{
		src: k.client,
		dst: k.client,
	}

	if a, _ := k.logAggregationMode(ctx, c.src); a != defaults.ConfigMapValueMonitorAggregatonNone {
		k.flowAggregation = true
	}

	if k.params.MultiCluster != "" && k.params.SingleNode {
		return nil, fmt.Errorf("single-node test can not be enabled with multi-cluster test")
	}

	// In single-cluster environment, automatically detect a single-node
	// environment so we can skip deploying tests which depend on multiple
	// nodes.
	if k.params.MultiCluster == "" && !k.params.SingleNode {
		daemonSet, err := k.client.GetDaemonSet(ctx, k.params.CiliumNamespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
		if err != nil {
			k.Log("❌ Unable to determine status of Cilium DaemonSet. Run \"cilium status\" for more details")
			return nil, fmt.Errorf("unable to determine status of Cilium DaemonSet: %w", err)
		}

		isSingleNode := false
		if daemonSet.Status.DesiredNumberScheduled == 1 {
			isSingleNode = true
		} else {
			nodes, err := k.client.ListNodes(ctx, metav1.ListOptions{})
			if err != nil {
				k.Log("❌ Unable to list nodes.")
				return nil, fmt.Errorf("unable to list nodes: %w", err)
			}

			numWorkerNodes := len(nodes.Items)
			for _, n := range nodes.Items {
				for _, t := range n.Spec.Taints {
					// cannot schedule connectivity test pods on
					// master node.
					if t.Key == "node-role.kubernetes.io/master" {
						numWorkerNodes--
					}
				}
			}

			isSingleNode = numWorkerNodes == 1
		}

		if isSingleNode {
			k.Log("ℹ️  Single node environment detected, enabling single node connectivity test")
			k.params.SingleNode = true
		}
	} else if k.params.MultiCluster != "" {
		dst, err := k8s.NewClient(k.params.MultiCluster, "")
		if err != nil {
			return nil, fmt.Errorf("unable to create Kubernetes client for remote cluster %q: %w", k.params.MultiCluster, err)
		}

		c.dst = dst

		if a, _ := k.logAggregationMode(ctx, c.dst); a != defaults.ConfigMapValueMonitorAggregatonNone {
			k.flowAggregation = true
		}
	}

	if k.flowAggregation {
		k.Log("ℹ️  Monitor aggregation detected, will skip some flow validation steps")
	}

	return c, nil
}

func (k *K8sConnectivityCheck) deploy(ctx context.Context) error {
	if k.params.ForceDeploy {
		if err := k.deleteDeployments(ctx, k.clients.src); err != nil {
			return err
		}
	}

	_, err := k.clients.src.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
	if err != nil {
		k.Log("✨ [%s] Creating namespace for connectivity check...", k.clients.src.ClusterName())
		_, err = k.clients.src.CreateNamespace(ctx, k.params.TestNamespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create namespace %s: %s", k.params.TestNamespace, err)
		}
	}

	if k.params.MultiCluster != "" {
		if k.params.ForceDeploy {
			if err := k.deleteDeployments(ctx, k.clients.dst); err != nil {
				return err
			}
		}

		_, err = k.clients.dst.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
		if err != nil {
			k.Log("✨ [%s] Creating namespace for connectivity check...", k.clients.dst.ClusterName())
			_, err = k.clients.dst.CreateNamespace(ctx, k.params.TestNamespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %s", k.params.TestNamespace, err)
			}
		}
	}

	_, err = k.clients.src.GetService(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Log("✨ [%s] Deploying echo-same-node service...", k.clients.src.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, serviceLabels, "http", 8080)
		_, err = k.clients.src.CreateService(ctx, k.params.TestNamespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	if k.params.MultiCluster != "" {
		_, err = k.clients.src.GetService(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			k.Log("✨ [%s] Deploying echo-other-node service...", k.clients.src.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)
			svc.ObjectMeta.Annotations = map[string]string{}
			svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"

			_, err = k.clients.src.CreateService(ctx, k.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}

	_, err = k.clients.src.GetDeployment(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Log("✨ [%s] Deploying same-node deployment...", k.clients.src.ClusterName())
		echoDeployment := newDeployment(deploymentParameters{
			Name:   echoSameNodeDeploymentName,
			Kind:   kindEchoName,
			Port:   8080,
			Image:  defaults.ConnectivityCheckJSONMockImage,
			Labels: map[string]string{"other": "echo"},
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
			ReadinessProbe: newLocalReadinessProbe(8080, "/"),
		})

		_, err = k.clients.src.CreateDeployment(ctx, k.params.TestNamespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoSameNodeDeploymentName, err)
		}
	}

	_, err = k.clients.src.GetDeployment(ctx, k.params.TestNamespace, ClientDeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Log("✨ [%s] Deploying client deployment...", k.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    ClientDeploymentName,
			Kind:    kindClientName,
			Port:    8080,
			Image:   defaults.ConnectivityCheckAlpineCurlImage,
			Command: []string{"/bin/ash", "-c", "sleep 10000000"},
		})
		_, err = k.clients.src.CreateDeployment(ctx, k.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", ClientDeploymentName, err)
		}
	}

	// 2nd client with label other=client
	_, err = k.clients.src.GetDeployment(ctx, k.params.TestNamespace, Client2DeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Log("✨ [%s] Deploying client2 deployment...", k.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    Client2DeploymentName,
			Kind:    kindClientName,
			Port:    8080,
			Image:   defaults.ConnectivityCheckAlpineCurlImage,
			Command: []string{"/bin/ash", "-c", "sleep 10000000"},
			Labels:  map[string]string{"other": "client"},
		})
		_, err = k.clients.src.CreateDeployment(ctx, k.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", Client2DeploymentName, err)
		}
	}

	if !k.params.SingleNode || k.params.MultiCluster != "" {
		_, err = k.clients.dst.GetService(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			k.Log("✨ [%s] Deploying echo-other-node service...", k.clients.dst.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)

			if k.params.MultiCluster != "" {
				svc.ObjectMeta.Annotations = map[string]string{}
				svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"
			}

			_, err = k.clients.dst.CreateService(ctx, k.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}

		_, err = k.clients.dst.GetDeployment(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			k.Log("✨ [%s] Deploying other-node deployment...", k.clients.dst.ClusterName())
			echoOtherNodeDeployment := newDeployment(deploymentParameters{
				Name:  echoOtherNodeDeploymentName,
				Kind:  kindEchoName,
				Port:  8080,
				Image: defaults.ConnectivityCheckJSONMockImage,
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
									},
								},
								TopologyKey: "kubernetes.io/hostname",
							},
						},
					},
				},
				ReadinessProbe: newLocalReadinessProbe(8080, "/"),
			})

			_, err = k.clients.dst.CreateDeployment(ctx, k.params.TestNamespace, echoOtherNodeDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %s", echoOtherNodeDeploymentName, err)
			}
		}
	}

	return nil
}

func (k *K8sConnectivityCheck) validateCiliumEndpoint(ctx context.Context, client k8sConnectivityImplementation, namespace, name string) error {
	k.Log("⌛ [%s] Waiting for CiliumEndpoint for pod %s to appear...", client.ClusterName(), namespace+"/"+name)
	for {
		_, err := client.GetCiliumEndpoint(ctx, k.params.TestNamespace, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return fmt.Errorf("aborted waiting for CiliumEndpoint for pod %s to appear: %w", name, ctx.Err())
		}
	}
}

func (k *K8sConnectivityCheck) waitForDeploymentsReady(ctx context.Context, client k8sConnectivityImplementation, deployments []string) error {
	k.Log("⌛ [%s] Waiting for deployments %s to become ready...", client.ClusterName(), deployments)

	ctx, cancel := context.WithTimeout(ctx, k.params.podReadyTimeout())
	defer cancel()
	for _, name := range deployments {
		for client.DeploymentIsReady(ctx, k.params.TestNamespace, name) != nil {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return fmt.Errorf("waiting for deployment %s to become ready has been interrupted: %w", name, ctx.Err())
			}
		}
	}

	return nil
}

func (k *K8sConnectivityCheck) RandomClientPod() *PodContext {
	for _, p := range k.clientPods {
		return &p
	}
	return nil
}

func (k *K8sConnectivityCheck) waitForService(ctx context.Context, client k8sConnectivityImplementation, service string) error {
	k.Log("⌛ [%s] Waiting for service %s to become ready...", client.ClusterName(), service)

	ctx, cancel := context.WithTimeout(ctx, k.params.serviceReadyTimeout())
	defer cancel()

	clientPod := k.RandomClientPod()
	if clientPod == nil {
		return fmt.Errorf("no client pod available")
	}

retry:
	if _, _, err := client.ExecInPodWithStderr(ctx, clientPod.Pod.Namespace, clientPod.Pod.Name, clientPod.Pod.Labels["name"], []string{"nslookup", service}); err != nil {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return fmt.Errorf("waiting for service %s timed out, last error: %s", service, err)
		}
		goto retry
	}

	return nil
}

func (k *K8sConnectivityCheck) validateDeployment(ctx context.Context) error {
	srcDeployments, dstDeployments := k.deploymentList()
	if err := k.waitForDeploymentsReady(ctx, k.clients.src, srcDeployments); err != nil {
		return err
	}
	if err := k.waitForDeploymentsReady(ctx, k.clients.dst, dstDeployments); err != nil {
		return err
	}

	k.ciliumPods = map[string]PodContext{}
	for _, client := range k.clients.clients() {
		ciliumPods, err := client.ListPods(ctx, k.ciliumNamespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
		if err != nil {
			return fmt.Errorf("unable to list Cilium pods: %s", err)
		}
		for _, ciliumPod := range ciliumPods.Items {
			// TODO: Can Cilium pod names collide across clusters?
			k.ciliumPods[ciliumPod.Name] = PodContext{
				K8sClient: client,
				Pod:       ciliumPod.DeepCopy(),
			}
		}
	}

	clientPods, err := k.client.ListPods(ctx, k.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	k.clientPods = map[string]PodContext{}
	for _, pod := range clientPods.Items {
		ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
		defer cancel()
		if err := k.validateCiliumEndpoint(ctx, k.clients.src, k.params.TestNamespace, pod.Name); err != nil {
			return err
		}

		k.clientPods[pod.Name] = PodContext{
			K8sClient: k.client,
			Pod:       pod.DeepCopy(),
		}
	}

	k.echoPods = map[string]PodContext{}
	for _, client := range k.clients.clients() {
		echoPods, err := client.ListPods(ctx, k.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %s", err)
		}
		for _, echoPod := range echoPods.Items {
			ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
			defer cancel()
			if err := k.validateCiliumEndpoint(ctx, client, k.params.TestNamespace, echoPod.Name); err != nil {
				return err
			}

			k.echoPods[echoPod.Name] = PodContext{
				K8sClient: client,
				Pod:       echoPod.DeepCopy(),
			}
		}
	}

	k.echoServices = map[string]ServiceContext{}
	for _, client := range k.clients.clients() {
		echoServices, err := client.ListServices(ctx, k.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo services: %s", err)
		}

		for _, echoService := range echoServices.Items {
			k.echoServices[echoService.Name] = ServiceContext{
				Service: echoService.DeepCopy(),
			}
		}
	}

	for serviceName := range k.echoServices {
		k.waitForService(ctx, k.client, serviceName)
	}

	k.externalWorkloads = map[string]ExternalWorkloadContext{}
	for _, client := range k.clients.clients() {
		externalWorkloads, err := client.ListCiliumExternalWorkloads(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("unable to list external workloads: %s", err)
		}
		for _, externalWorkload := range externalWorkloads.Items {
			k.externalWorkloads[externalWorkload.Name] = ExternalWorkloadContext{
				ExternalWorkload: externalWorkload.DeepCopy(),
			}
		}
	}

	k.policies = map[string]*ciliumv2.CiliumNetworkPolicy{}

	return nil
}

func (k *K8sConnectivityCheck) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sConnectivityCheck) StoreLastTimestamp(pod string, t time.Time) {
	k.lastFlowTimestamps[pod] = t
}

func (k *K8sConnectivityCheck) LoadLastTimestamp(pod string) time.Time {
	return k.lastFlowTimestamps[pod]
}

func (k *K8sConnectivityCheck) Header(format string, a ...interface{}) {
	k.Log("")
	k.Log("---------------------------------------------------------------------------------------------------------------------")
	k.Log(format, a...)
	k.Log("---------------------------------------------------------------------------------------------------------------------")
}

func (k *K8sConnectivityCheck) HubbleClient() observer.ObserverClient {
	return k.hubbleClient
}

func (k *K8sConnectivityCheck) PrintFlows() bool {
	return k.params.PrintFlows
}

func (k *K8sConnectivityCheck) AllFlows() bool {
	return k.params.AllFlows
}

func (k *K8sConnectivityCheck) Verbose() bool {
	return k.verbose
}

func (k *K8sConnectivityCheck) SetVerbose(verbose bool) {
	k.verbose = verbose
}

func (k *K8sConnectivityCheck) ResetVerbose() {
	k.verbose = k.params.Verbose
}

func (k *K8sConnectivityCheck) FlowAggregation() bool {
	return k.flowAggregation
}

func (k *K8sConnectivityCheck) EchoPods() map[string]PodContext {
	return k.echoPods
}

func (k *K8sConnectivityCheck) ClientPods() map[string]PodContext {
	return k.clientPods
}

func (k *K8sConnectivityCheck) EchoServices() map[string]ServiceContext {
	return k.echoServices
}

func (k *K8sConnectivityCheck) ExternalWorkloads() map[string]ExternalWorkloadContext {
	return k.externalWorkloads
}

func (k *K8sConnectivityCheck) PostTestSleepDuration() time.Duration {
	return k.params.PostTestSleepDuration
}

func (k *K8sConnectivityCheck) Report(r TestResult) {
	if k.results == nil {
		k.results = TestResults{}
	}

	if _, ok := k.results[r.Name]; ok {
		k.Log("❌ Overwriting results for test $q, failing the test", r.Name)
		r.Failures++
	}
	k.results[r.Name] = r
}

func (k *K8sConnectivityCheck) Run(ctx context.Context, tests ...ConnectivityTest) error {
	c, err := k.initClients(ctx)
	if err != nil {
		return err
	}
	k.clients = c

	err = k.deploy(ctx)
	if err != nil {
		return err
	}

	if err := k.validateDeployment(ctx); err != nil {
		return err
	}

	if k.params.Hubble {
		k.Log("🔭 Enabling Hubble telescope...")
		if err := k.enableHubbleClient(ctx); err != nil {
			return fmt.Errorf("unable to create hubble client: %s", err)
		}
	}

	for _, test := range tests {
		if test.PolicyOnly() || k.params.testEnabled(test.Name()) {
			test.Run(ctx, k)
		}
	}

	k.Header("📋 Test Report")
	failed := k.results.Failed()
	warnings := k.results.Warnings()
	if failed == 0 {
		k.Log("✅ %d/%d tests successful (%d warnings)", len(k.results), len(k.results), warnings)
	} else {
		k.Log("❌ %d/%d tests failed (%d warnings)", failed, len(k.results), warnings)

		var testStatus []string
		for _, result := range k.results {
			testStatus = append(testStatus, result.String())
		}
		k.Log("")
		k.Log("Failed tests: " + strings.Join(testStatus, ", "))

		return fmt.Errorf("%d tests failed", failed)
	}

	return nil
}
