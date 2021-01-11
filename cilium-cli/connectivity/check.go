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

type K8sConnectivityCheck struct {
	clients         *deploymentClients
	client          k8sConnectivityImplementation
	params          Parameters
	ciliumNamespace string
	hubbleClient    observer.ObserverClient
	clientPods      *corev1.PodList
	echoPods        map[string]string
}

func NewK8sConnectivityCheck(client k8sConnectivityImplementation, p Parameters) *K8sConnectivityCheck {
	return &K8sConnectivityCheck{
		client:          client,
		ciliumNamespace: "kube-system",
		params:          p,
	}
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

func (k *K8sConnectivityCheck) getFlows(ctx context.Context, since time.Time, pod string) (*flowsSet, error) {
	set := &flowsSet{}

	if k.hubbleClient == nil {
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

	b, err := k.hubbleClient.GetFlows(ctx, request)
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

func (k *K8sConnectivityCheck) validatePodToPod(ctx context.Context) {
	for _, clientPod := range k.clientPods.Items {
		for echoName, echoIP := range k.echoPods {
			var (
				srcPod     = connectivityCheckNamespace + "/" + clientPod.Name
				dstPod     = connectivityCheckNamespace + "/" + echoName
				printFlows = k.params.PrintFlows
				success    = true
			)

			k.Header("🔌 Validating from pod %s to pod %s...", srcPod, dstPod)
			now := time.Now()
			_, err := k.client.ExecInPod(ctx, connectivityCheckNamespace, clientPod.Name, clientDeploymentName, curlCommand(echoIP+":8080"))
			if err != nil {
				k.Log("❌ curl connectivity check command failed: %s", err)
				printFlows = true
			}

			srcFlows, err := k.getFlows(ctx, now.Add(-2*time.Second), srcPod)
			if err != nil {
				k.Log("Unable to retrieve flows of pod %s: %s", srcPod, err)
			}

			dstFlows, err := k.getFlows(ctx, now.Add(-2*time.Second), dstPod)
			if err != nil {
				k.Log("Unable to retrieve flows of pod %s: %s", dstPod, err)
			}

			if k.params.Hubble {
				if !k.Validate(srcPod, srcFlows, []FilterPair{
					{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
					{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "Found RST"},
					{Filter: TCPFilter(echoIP, clientPod.Status.PodIP, 8080, 0, true, true, false, false), Expect: true, Msg: "SYN-ACK not found"},
					{Filter: TCPFilter(echoIP, clientPod.Status.PodIP, 8080, 0, false, true, true, false), Expect: true, Msg: "FIN-ACK not found"},
				}) {
					printFlows = true
				}

				if !k.Validate(dstPod, dstFlows, []FilterPair{
					{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
					{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "Found RST"},
					{Filter: TCPFilter(clientPod.Status.PodIP, echoIP, 0, 8080, true, false, false, false), Expect: true, Msg: "SYN not found"},
					{Filter: TCPFilter(clientPod.Status.PodIP, echoIP, 0, 8080, false, true, true, false), Expect: true, Msg: "FIN not found"},
				}) {
					printFlows = true
				}
			}

			if printFlows {
				k.Print(srcPod, srcFlows)
				k.Print(dstPod, dstFlows)
			}

			if success {
				k.Log("✅ client pod %s was able to communicate with echo pod %s (%s)", clientPod.Name, echoName, echoIP)
			} else {
				k.Log("❌ client pod %s was not able to communicate with echo pod %s (%s)", clientPod.Name, echoName, echoIP)
			}

			k.Relax()
		}
	}
}

func (k *K8sConnectivityCheck) validatePodToService(ctx context.Context) {
	services := []string{echoSameNodeDeploymentName}
	if !k.params.SingleNode {
		services = append(services, echoOtherNodeDeploymentName)
	}

	for _, clientPod := range k.clientPods.Items {
		for _, echoSvc := range services {
			var (
				srcPod     = connectivityCheckNamespace + "/" + clientPod.Name
				printFlows = k.params.PrintFlows
				success    = true
			)

			k.Header("🔌 Validating from pod %s to service %s...", srcPod, echoSvc)
			now := time.Now()
			_, err := k.clients.src.ExecInPod(ctx, connectivityCheckNamespace, clientPod.Name, clientDeploymentName, curlCommand(echoSvc+":8080"))
			if err != nil {
				k.Log("❌ curl connectivity check command failed: %s", err)
				success = false
			}

			srcFlows, err := k.getFlows(ctx, now.Add(-2*time.Second), srcPod)
			if err != nil {
				k.Log("Unable to retrieve flows of pod %s: %s", srcPod, err)
			}

			if k.params.Hubble {
				if !k.Validate(srcPod, srcFlows, []FilterPair{
					{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
					{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "Found RST"},
					{Filter: UDPFilter(clientPod.Status.PodIP, "", 0, 53), Expect: true, Msg: "DNS request not found"},
					{Filter: UDPFilter("", clientPod.Status.PodIP, 53, 0), Expect: true, Msg: "DNS response not found"},
					{Filter: TCPFilter(clientPod.Status.PodIP, "", 0, 8080, true, false, false, false), Expect: true, Msg: "SYN not found"},
					{Filter: TCPFilter("", clientPod.Status.PodIP, 8080, 0, true, true, false, false), Expect: true, Msg: "SYN-ACK not found"},
					{Filter: TCPFilter(clientPod.Status.PodIP, "", 0, 8080, false, true, true, false), Expect: true, Msg: "FIN not found"},
					{Filter: TCPFilter("", clientPod.Status.PodIP, 8080, 0, false, true, true, false), Expect: true, Msg: "FIN-ACK not found"},
				}) {
					printFlows = true
				}
			}

			if printFlows {
				k.Print(srcPod, srcFlows)
			}

			if success {
				k.Log("✅ client pod %s was able to communicate with service %s", clientPod.Name, echoSvc)
			} else {
				k.Log("❌ client pod %s was not able to communicate with service %s", clientPod.Name, echoSvc)
			}

			k.Relax()
		}
	}
}

func (k *K8sConnectivityCheck) validatePodToWorld(ctx context.Context) {
	for _, clientPod := range k.clientPods.Items {
		var (
			success    = true
			printFlows = k.params.PrintFlows
			srcPod     = connectivityCheckNamespace + "/" + clientPod.Name
		)

		k.Header("🔌 Validating from pod %s to outside of cluster...", srcPod)
		now := time.Now()
		_, err := k.clients.src.ExecInPod(ctx, connectivityCheckNamespace, clientPod.Name, clientDeploymentName, curlCommand("https://google.com"))
		if err != nil {
			k.Log("❌ curl connectivity check command failed: %s", err)
			success = false
			printFlows = true
		}

		srcFlows, err := k.getFlows(ctx, now.Add(-2*time.Second), srcPod)
		if err != nil {
			k.Log("unable to retrieve flows of pod %s: %s", srcPod, err)
		}

		if k.params.Hubble {
			if !k.Validate(srcPod, srcFlows, []FilterPair{
				{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
				{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "Found RST"},
				{Filter: UDPFilter(clientPod.Status.PodIP, "", 0, 53), Expect: true, Msg: "DNS request not found"},
				{Filter: UDPFilter("", clientPod.Status.PodIP, 53, 0), Expect: true, Msg: "DNS response not found"},
				{Filter: TCPFilter(clientPod.Status.PodIP, "", 0, 443, true, false, false, false), Expect: true, Msg: "SYN not found"},
				{Filter: TCPFilter("", clientPod.Status.PodIP, 443, 0, true, true, false, false), Expect: true, Msg: "SYN-ACK not found"},
				{Filter: TCPFilter(clientPod.Status.PodIP, "", 0, 443, false, true, true, false), Expect: true, Msg: "FIN not found"},
				{Filter: TCPFilter("", clientPod.Status.PodIP, 443, 0, false, true, true, false), Expect: true, Msg: "FIN-ACK not found"},
			}) {
				printFlows = true
			}
		}

		if printFlows {
			k.Print(srcPod, srcFlows)
		}

		if success {
			k.Log("✅ client pod %s was able to communicate with google.com", clientPod.Name)
		} else {
			k.Log("❌ client pod %s was not able to communicate with google.com", clientPod.Name)
		}

		k.Relax()
	}
}

func (k *K8sConnectivityCheck) validatePodToHost(ctx context.Context) {
	for _, clientPod := range k.clientPods.Items {
		var (
			success    = true
			printFlows = k.params.PrintFlows
			srcPod     = connectivityCheckNamespace + "/" + clientPod.Name
		)

		k.Header("🔌 Validating from pod %s to local host...", srcPod)
		now := time.Now()
		cmd := []string{"ping", "-c", "3", clientPod.Status.HostIP}
		_, err := k.client.ExecInPod(ctx, connectivityCheckNamespace, clientPod.Name, clientDeploymentName, cmd)
		if err != nil {
			k.Log("❌ ping command failed: %s", err)
			success = false
			printFlows = true
		}

		srcFlows, err := k.getFlows(ctx, now.Add(-2*time.Second), srcPod)
		if err != nil {
			k.Log("Unable to retrieve flows of pod %s: %s", srcPod, err)
		}

		if k.params.Hubble {
			if !k.Validate(srcPod, srcFlows, []FilterPair{
				{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
				{Filter: ICMPFilter(clientPod.Status.PodIP, clientPod.Status.HostIP, 8), Expect: true, Msg: "ICMP request not found"},
				{Filter: ICMPFilter(clientPod.Status.HostIP, clientPod.Status.PodIP, 0), Expect: true, Msg: "ICMP response not found"},
			}) {
				printFlows = true
			}
		}

		if printFlows {
			k.Print(srcPod, srcFlows)
		}

		if success {
			k.Log("✅ client pod %s was able to communicate with local host", clientPod.Name)
		} else {
			k.Log("❌ client pod %s was not able to communicate with local host", clientPod.Name)
		}

		k.Relax()
	}
}

func (k *K8sConnectivityCheck) Relax() {
	time.Sleep(2 * time.Second)
}

type Parameters struct {
	CiliumNamespace string
	SingleNode      bool
	PrintFlows      bool
	ForceDeploy     bool
	Hubble          bool
	HubbleServer    string
	MultiCluster    string
	PostRelax       time.Duration
	PreFlowRelax    time.Duration
	Writer          io.Writer
}

func (p Parameters) ciliumEndpointTimeout() time.Duration {
	return 30 * time.Second
}

func (p Parameters) podReadyTimeout() time.Duration {
	return 30 * time.Second
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
			Image: "docker.io/cilium/json-mock:1.2",
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
		clientDeployment := newDeployment(deploymentParameters{Name: clientDeploymentName, Kind: kindClientName, Port: 8080, Image: "docker.io/byrnedo/alpine-curl:0.1.8", Command: []string{"/bin/ash", "-c", "sleep 10000000"}})
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
				Image: "docker.io/cilium/json-mock:1.2",
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
	var err error

	srcDeployments, dstDeployments := k.deploymentList()
	if err := k.waitForDeploymentsReady(ctx, k.clients.src, srcDeployments); err != nil {
		return err
	}
	if err := k.waitForDeploymentsReady(ctx, k.clients.dst, dstDeployments); err != nil {
		return err
	}

	k.clientPods, err = k.client.ListPods(ctx, connectivityCheckNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	for _, pod := range k.clientPods.Items {
		ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
		defer cancel()
		if err := k.validateCiliumEndpoint(ctx, k.clients.src, connectivityCheckNamespace, pod.Name); err != nil {
			return err
		}
	}

	k.echoPods = map[string]string{}
	for _, client := range k.clients.clients() {
		echoPods, err := client.ListPods(ctx, connectivityCheckNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %s", err)
		}
		for _, echoPod := range echoPods.Items {
			k.echoPods[echoPod.Name] = echoPod.Status.PodIP

			ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
			defer cancel()
			if err := k.validateCiliumEndpoint(ctx, client, connectivityCheckNamespace, echoPod.Name); err != nil {
				return err
			}
		}
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

	k.validatePodToPod(ctx)
	k.validatePodToWorld(ctx)
	k.validatePodToHost(ctx)
	k.validatePodToService(ctx)

	return nil
}
