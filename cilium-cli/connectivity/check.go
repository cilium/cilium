// Copyright 2020 Authors of Cilium
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

package connectivity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

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
)

const (
	connectivityCheckNamespace  = "cilium-test"
	clientDeploymentName        = "client"
	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
)

func curlCommand(target string) []string {
	return []string{"curl", "-sS", "--fail", "--connect-timeout", "5", "-o", "/dev/null", target}
}

func newService(name string, selector map[string]string, portName string, port int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Name: name, Port: int32(port)},
			},
			Selector: selector,
		},
	}
}

type deploymentParameters struct {
	Name     string
	Kind     string
	Image    string
	Replicas int
	Port     int
	Command  []string
	Affinity *corev1.Affinity
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	replicas32 := int32(p.Replicas)
	return &appsv1.Deployment{
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
}

type k8sConnectivityImplementation interface {
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
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	GetCiliumEndpoint(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*ciliumv2.CiliumEndpoint, error)
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	ClusterName() (name string)
}

// PodContext is a pod acting as a peer in a connectivity test
type PodContext struct {
	// K8sClient is the Kubernetes client of the cluster this pod is
	// running in
	k8sClient k8sConnectivityImplementation

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

// ServiceContext is a service acting as a peer in a connectivity test
type ServiceContext struct {
	// Namespace is the namespace the service is deployed in
	Namespace string

	// ServiceName is the name of the service
	ServiceName string
}

// Name returns the absolute name of the service
func (s ServiceContext) Name() string {
	return s.Namespace + "/" + s.ServiceName
}

// Address returns the network address of the service
func (s ServiceContext) Address() string {
	return s.ServiceName
}

// NetworkEndpointContext is a network endpoint acting as a peer in a connectivity test
type NetworkEndpointContext struct {
	// Peer is the network address
	Peer string
}

// Name is the absolute name of the network endpoint
func (n NetworkEndpointContext) Name() string {
	return n.Peer
}

// Address it the network address of the network endpoint
func (n NetworkEndpointContext) Address() string {
	return n.Peer
}

// TestContext is the context a test uses to interact with the test framework
type TestContext interface {
	// EchoPods returns a map of all deployed echo pods
	EchoPods() map[string]PodContext

	// ClientPods returns a map of all deployed client pods
	ClientPods() map[string]PodContext

	// EchoServices returns a map of all deployed echo services
	EchoServices() map[string]ServiceContext

	// Log is used to log a status update
	Log(format string, a ...interface{})

	// Header logs a header to segment tests
	Header(format string, a ...interface{})

	// Relax is invoked in between tests to relax the test framework
	Relax()

	// HubbleClient returns the Hubble client to retrieve flow logs
	HubbleClient() observer.ObserverClient

	// PrintFlows returns true if flow logs should be printed
	PrintFlows() bool
}

// TestRun is the state of an individual test run
type TestRun struct {
	// name is the name of the test being run
	name string

	// context is the test context of the framework
	context TestContext

	// src is the peer used as the source (client)
	src TestPeer

	// dst is the peer used as the destination (server)
	dst TestPeer

	// flows is a map of all flow logs, indexed by pod name
	flows map[string]*flowsSet

	// started is the timestamp the test started
	started time.Time

	// failures is the number of failures encountered in this test run
	failures int
}

// NewTestRun creates a new test run
func NewTestRun(name string, c TestContext, src, dst TestPeer) *TestRun {
	c.Header("🔌 [%s] Testing %s -> %s...", name, src.Name(), dst.Name())

	return &TestRun{
		name:    name,
		context: c,
		src:     src,
		dst:     dst,
		started: time.Now(),
		flows:   map[string]*flowsSet{},
	}
}

// Failure must be called when a failure is detected performing the test
func (t *TestRun) Failure(format string, a ...interface{}) {
	t.context.Log("❌ "+format, a...)
	t.failures++
}

func (t *TestRun) printFlows(pod string, f *flowsSet) {
	if f == nil {
		t.context.Log("📄 No flows recorded for pod %s", pod)
		return
	}

	t.context.Log("📄 Flow logs of pod %s:", pod)
	printer := hubprinter.New(hubprinter.Compact())
	defer printer.Close()
	for _, flow := range f.flows {
		if err := printer.WriteProtoFlow(flow); err != nil {
			t.context.Log("Unable to print flow: %s", err)
		}
	}
}

// ValidateFlows retrieves the flow pods of the specified pod and validates
// that all filters find a match. On failure, t.Failure() is called.
func (t *TestRun) ValidateFlows(ctx context.Context, pod string, filter []FilterPair) {
	hubbleClient := t.context.HubbleClient()
	if hubbleClient == nil {
		return
	}

	flows, ok := t.flows[pod]
	if !ok {
		var err error
		flows, err = getFlows(ctx, hubbleClient, t.started.Add(-2*time.Second), pod)
		if err != nil {
			t.context.Log("Unable to retrieve flows of pod %s: %s", pod, err)
			t.Failure("Unable to retrieve flows of pod %q: %s", pod, err)
			return
		}

		t.flows[pod] = flows
	}

	for _, p := range filter {
		if flows.Contains(p.Filter) != p.Expect {
			t.Failure("%s in pod %s", p.Msg, pod)
		}
	}
}

// End is called at the end of a test run to signal completion. It must be
// called for both successful and failed test runs. It will log a summary and
// print flow logs if necessary.
func (t *TestRun) End() {
	if t.context.PrintFlows() || t.failures > 0 {
		for name, flows := range t.flows {
			t.printFlows(name, flows)
		}
	}

	prefix := "✅"
	if t.failures > 0 {
		prefix = "❌"
	}

	t.context.Log("%s [%s] %s (%s) -> %s (%s)",
		prefix, t.name,
		t.src.Name(), t.src.Address(),
		t.dst.Name(), t.dst.Address())

	t.context.Relax()
}

// TestPeer is the abstraction used for all peer types (pods, services, IPs,
// DNS names) used for connectivity testing
type TestPeer interface {
	// Name must return the absolute name of the peer
	Name() string

	// Address must return the network address of the peer. This can be a
	// DNS name or an IP address.
	Address() string
}

// ConnectivityTest is the interface to implement for all connectivity tests
type ConnectivityTest interface {
	// Name must return the name of the test
	Name() string

	// Run is called to run the connectivity test
	Run(ctx context.Context, c TestContext)
}

type K8sConnectivityCheck struct {
	client          k8sConnectivityImplementation
	ciliumNamespace string
	hubbleClient    observer.ObserverClient
	params          Parameters
	clients         *deploymentClients
	echoPods        map[string]PodContext
	clientPods      map[string]PodContext
	echoServices    map[string]ServiceContext
	tests           map[string]struct{}
}

func NewK8sConnectivityCheck(client k8sConnectivityImplementation, p Parameters) *K8sConnectivityCheck {
	k := &K8sConnectivityCheck{
		client:          client,
		ciliumNamespace: "kube-system",
		params:          p,
	}

	if len(p.Tests) > 0 {
		k.tests = map[string]struct{}{}
		for _, testName := range p.Tests {
			k.tests[testName] = struct{}{}
		}
	}

	return k
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
	} else {
		k.Log("ℹ️  Hubble is OK, flows: %d/%d", status.NumFlows, status.MaxFlows)
	}

	return nil
}

type flowsSet struct {
	flows []*observer.GetFlowsResponse
}

func getFlows(ctx context.Context, hubbleClient observer.ObserverClient, since time.Time, pod string) (*flowsSet, error) {
	set := &flowsSet{}

	if hubbleClient == nil {
		return set, nil
	}

	time.Sleep(time.Second)

	sinceTimestamp, err := ptypes.TimestampProto(since)
	if err != nil {
		return nil, fmt.Errorf("invalid since value %s: %s", since, err)
	}

	filter := []*flow.FlowFilter{
		{SourcePod: []string{pod}},
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

type FlowFilterFunc func(flow *flow.Flow) bool

func (f *flowsSet) Contains(fn FlowFilterFunc) bool {
	if f == nil {
		return false
	}

	for _, res := range f.flows {
		if fn(res.GetFlow()) {
			return true
		}
	}

	return false
}

type FilterPair struct {
	Filter FlowFilterFunc
	Msg    string
	Expect bool
}

func (k *K8sConnectivityCheck) Validate(pod string, f *flowsSet, filter []FilterPair) (success bool) {
	for _, p := range filter {
		if f.Contains(p.Filter) != p.Expect {
			k.Log("❌ %s in pod %s", p.Msg, pod)
			success = false
		}
	}
	return
}

func DropFilter() FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		r := flow.GetDropReason()
		return r != uint32(0)
	}
}

func ipFilter(flow *flow.Flow, srcIP, dstIP string) bool {
	ip := flow.GetIP()
	if ip == nil {
		return false
	}
	if srcIP != "" && ip.Source != srcIP {
		return false
	}

	if dstIP != "" && ip.Destination != dstIP {
		return false
	}

	return true
}

func ICMPFilter(srcIP, dstIP string, typ uint32) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		if !ipFilter(flow, srcIP, dstIP) {
			return false
		}

		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		icmp := l4.GetICMPv4()
		if icmp == nil {
			return false
		}

		if icmp.Type != typ {
			return false
		}

		return true
	}
}

func UDPFilter(srcIP, dstIP string, srcPort, dstPort int) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		if !ipFilter(flow, srcIP, dstIP) {
			return false
		}

		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		udp := l4.GetUDP()
		if udp == nil {
			return false
		}

		if srcPort != 0 && udp.SourcePort != uint32(srcPort) {
			return false
		}

		if dstPort != 0 && udp.DestinationPort != uint32(dstPort) {
			return false
		}

		return true
	}
}

func TCPFilter(srcIP, dstIP string, srcPort, dstPort int, syn, ack, fin, rst bool) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		if !ipFilter(flow, srcIP, dstIP) {
			return false
		}

		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		tcp := l4.GetTCP()
		if tcp == nil || tcp.Flags == nil {
			return false
		}

		if srcPort != 0 && tcp.SourcePort != uint32(srcPort) {
			return false
		}

		if dstPort != 0 && tcp.DestinationPort != uint32(dstPort) {
			return false
		}

		if tcp.Flags.SYN != syn || tcp.Flags.ACK != ack || tcp.Flags.FIN != fin || tcp.Flags.RST != rst {
			return false
		}

		return true
	}
}

func (k *K8sConnectivityCheck) Print(pod string, f *flowsSet) {
	if f == nil {
		k.Log("📄 No flows recorded for pod %s", pod)
		return
	}

	k.Log("📄 Flow logs of pod %s:", pod)
	printer := hubprinter.New(hubprinter.Compact())
	defer printer.Close()
	for _, flow := range f.flows {
		if err := printer.WriteProtoFlow(flow); err != nil {
			k.Log("Unable to print flow: %s", err)
		}
	}
}

func (k *K8sConnectivityCheck) Relax() {
	// Only sleep between tests when Hubble flow validation is enabled.
	// Otherwise, tests can be run as quickly as possible.
	if k.params.Hubble {
		time.Sleep(2 * time.Second)
	}
}

type Parameters struct {
	CiliumNamespace string
	SingleNode      bool
	PrintFlows      bool
	ForceDeploy     bool
	Hubble          bool
	HubbleServer    string
	MultiCluster    string
	Tests           []string
	PostRelax       time.Duration
	PreFlowRelax    time.Duration
	Writer          io.Writer
}

func (p Parameters) ciliumEndpointTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) podReadyTimeout() time.Duration {
	return 5 * time.Minute
}

func (k *K8sConnectivityCheck) deleteDeployments(ctx context.Context, client k8sConnectivityImplementation) error {
	k.Log("🔥 [%s] Deleting connectivity check deployments...", client.ClusterName())
	client.DeleteDeployment(ctx, connectivityCheckNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteDeployment(ctx, connectivityCheckNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteDeployment(ctx, connectivityCheckNamespace, clientDeploymentName, metav1.DeleteOptions{})
	client.DeleteService(ctx, connectivityCheckNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteService(ctx, connectivityCheckNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	client.DeleteNamespace(ctx, connectivityCheckNamespace, metav1.DeleteOptions{})

	_, err := client.GetNamespace(ctx, connectivityCheckNamespace, metav1.GetOptions{})
	if err == nil {
		k.Log("⌛ [%s] Waiting for namespace %s to disappear", client.ClusterName(), connectivityCheckNamespace)
		for err == nil {
			time.Sleep(time.Second)
			_, err = client.GetNamespace(ctx, connectivityCheckNamespace, metav1.GetOptions{})
		}
	}

	return nil
}

func (k *K8sConnectivityCheck) deploymentList() (srcList []string, dstList []string) {
	srcList = []string{clientDeploymentName, echoSameNodeDeploymentName}

	if k.params.MultiCluster != "" || !k.params.SingleNode {
		dstList = append(dstList, echoOtherNodeDeploymentName)
	}

	return srcList, dstList
}

type deploymentClients struct {
	dstInOtherCluster bool
	src               k8sConnectivityImplementation
	dst               k8sConnectivityImplementation
}

func (d *deploymentClients) clients() []k8sConnectivityImplementation {
	if d.dstInOtherCluster {
		return []k8sConnectivityImplementation{d.src, d.dst}
	}
	return []k8sConnectivityImplementation{d.src}
}

func (k *K8sConnectivityCheck) initClients(ctx context.Context) (*deploymentClients, error) {
	c := &deploymentClients{
		src: k.client,
		dst: k.client,
	}

	// In single-cluster environment, automatically detect a single-node
	// environment so we can skip deploying tests which depend on multiple
	// nodes
	if k.params.MultiCluster == "" {
		daemonSet, err := k.client.GetDaemonSet(ctx, k.params.CiliumNamespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
		if err != nil {
			k.Log("❌ Unable to determine status of Cilium DaemonSet. Run \"cilium status\" for more details")
			return nil, fmt.Errorf("Unable to determine status of Cilium DaemonSet: %w", err)
		}

		if daemonSet.Status.DesiredNumberScheduled == 1 && !k.params.SingleNode {
			k.Log("ℹ️  Single node environment detected, enabling single node connectivity test")
			k.params.SingleNode = true
		}
	} else {
		dst, err := k8s.NewClient(k.params.MultiCluster, "")
		if err != nil {
			return nil, fmt.Errorf("unable to create Kubernetes client for remote cluster %q: %w", k.params.MultiCluster, err)
		}

		c.dst = dst
		c.dstInOtherCluster = true
	}

	return c, nil
}

func (k *K8sConnectivityCheck) deploy(ctx context.Context) error {
	var srcDeploymentNeeded, dstDeploymentNeeded bool

	if k.params.ForceDeploy {
		if err := k.deleteDeployments(ctx, k.clients.src); err != nil {
			return err
		}
	}

	_, err := k.clients.src.GetNamespace(ctx, connectivityCheckNamespace, metav1.GetOptions{})
	if err != nil {
		srcDeploymentNeeded = true
		// In a single cluster environment, the source client is also
		// responsibel for destination deployments
		if k.params.MultiCluster == "" {
			dstDeploymentNeeded = true
		}
		k.Log("✨ [%s] Creating namespace for connectivity check...", k.clients.src.ClusterName())
		_, err = k.clients.src.CreateNamespace(ctx, connectivityCheckNamespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create namespace %s: %s", connectivityCheckNamespace, err)
		}
	}

	if k.params.MultiCluster != "" {
		if k.params.ForceDeploy {
			if err := k.deleteDeployments(ctx, k.clients.dst); err != nil {
				return err
			}
		}

		_, err = k.clients.dst.GetNamespace(ctx, connectivityCheckNamespace, metav1.GetOptions{})
		if err != nil {
			dstDeploymentNeeded = true
			k.Log("✨ [%s] Creating namespace for connectivity check...", k.clients.dst.ClusterName())
			_, err = k.clients.dst.CreateNamespace(ctx, connectivityCheckNamespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %s", connectivityCheckNamespace, err)
			}
		}
	}

	if srcDeploymentNeeded {
		k.Log("✨ [%s] Deploying echo-same-node service...", k.clients.src.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, "http", 8080)
		_, err = k.clients.src.CreateService(ctx, connectivityCheckNamespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		if k.params.MultiCluster != "" {
			k.Log("✨ [%s] Deploying echo-other-node service...", k.clients.src.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, "http", 8080)
			svc.ObjectMeta.Annotations = map[string]string{}
			svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"

			_, err = k.clients.src.CreateService(ctx, connectivityCheckNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}

		echoDeployment := newDeployment(deploymentParameters{
			Name:  echoSameNodeDeploymentName,
			Kind:  kindEchoName,
			Port:  8080,
			Image: "quay.io/cilium/json-mock:1.2",
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{clientDeploymentName}},
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
		})

		_, err = k.clients.src.CreateDeployment(ctx, connectivityCheckNamespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoSameNodeDeploymentName, err)
		}

		k.Log("✨ [%s] Deploying client service...", k.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{Name: clientDeploymentName, Kind: kindClientName, Port: 8080, Image: "quay.io/cilium/alpine-curl:1.0", Command: []string{"/bin/ash", "-c", "sleep 10000000"}})
		_, err = k.clients.src.CreateDeployment(ctx, connectivityCheckNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", clientDeploymentName, err)
		}
	}

	if dstDeploymentNeeded {
		if !k.params.SingleNode || k.params.MultiCluster != "" {
			k.Log("✨ [%s] Deploying echo-other-node service...", k.clients.dst.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, "http", 8080)

			if k.params.MultiCluster != "" {
				svc.ObjectMeta.Annotations = map[string]string{}
				svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"
			}

			_, err = k.clients.dst.CreateService(ctx, connectivityCheckNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}

			echoOtherNodeDeployment := newDeployment(deploymentParameters{
				Name:  echoOtherNodeDeploymentName,
				Kind:  kindEchoName,
				Port:  8080,
				Image: "quay.io/cilium/json-mock:1.2",
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{clientDeploymentName}},
									},
								},
								TopologyKey: "kubernetes.io/hostname",
							},
						},
					},
				},
			})

			_, err = k.clients.dst.CreateDeployment(ctx, connectivityCheckNamespace, echoOtherNodeDeployment, metav1.CreateOptions{})
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
		_, err := client.GetCiliumEndpoint(ctx, connectivityCheckNamespace, name, metav1.GetOptions{})
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
		for client.DeploymentIsReady(ctx, connectivityCheckNamespace, name) != nil {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return fmt.Errorf("waiting for deployment %s to become ready has been interrupted: %w", name, ctx.Err())
			}
		}
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

	clientPods, err := k.client.ListPods(ctx, connectivityCheckNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	k.clientPods = map[string]PodContext{}
	for _, pod := range clientPods.Items {
		ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
		defer cancel()
		if err := k.validateCiliumEndpoint(ctx, k.clients.src, connectivityCheckNamespace, pod.Name); err != nil {
			return err
		}

		k.clientPods[pod.Name] = PodContext{
			k8sClient: k.client,
			Pod:       pod.DeepCopy(),
		}
	}

	k.echoPods = map[string]PodContext{}
	for _, client := range k.clients.clients() {
		echoPods, err := client.ListPods(ctx, connectivityCheckNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %s", err)
		}
		for _, echoPod := range echoPods.Items {
			ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
			defer cancel()
			if err := k.validateCiliumEndpoint(ctx, client, connectivityCheckNamespace, echoPod.Name); err != nil {
				return err
			}

			k.echoPods[echoPod.Name] = PodContext{
				k8sClient: client,
				Pod:       echoPod.DeepCopy(),
			}
		}
	}

	k.echoServices = map[string]ServiceContext{}
	k.echoServices[echoSameNodeDeploymentName] = ServiceContext{Namespace: connectivityCheckNamespace, ServiceName: echoSameNodeDeploymentName}
	if !k.params.SingleNode {
		k.echoServices[echoOtherNodeDeploymentName] = ServiceContext{Namespace: connectivityCheckNamespace, ServiceName: echoOtherNodeDeploymentName}
	}

	return nil
}

func (k *K8sConnectivityCheck) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sConnectivityCheck) Header(format string, a ...interface{}) {
	k.Log("-------------------------------------------------------------------------------------------")
	k.Log(format, a...)
	k.Log("-------------------------------------------------------------------------------------------")
}

func (k *K8sConnectivityCheck) HubbleClient() observer.ObserverClient {
	return k.hubbleClient
}

func (k *K8sConnectivityCheck) PrintFlows() bool {
	return k.params.PrintFlows
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

var tests = []ConnectivityTest{
	&connectivityTestPodToPod{},
	&connectivityTestPodToService{},
	&connectivityTestPodToWorld{},
	&connectivityTestPodToHost{},
}

func (k *K8sConnectivityCheck) Run(ctx context.Context) error {
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
		if k.tests != nil {
			if _, ok := k.tests[test.Name()]; !ok {
				continue
			}
		}
		test.Run(ctx, k)
	}

	return nil
}
