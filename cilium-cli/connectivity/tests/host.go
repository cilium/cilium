// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// PodToHost sends an ICMP ping from all client Pods to all nodes
// in the test context.
func PodToHost() check.Scenario {
	return &podToHost{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToHost implements a Scenario.
type podToHost struct {
	check.ScenarioBase
}

func (s *podToHost) Name() string {
	return "pod-to-host"
}

func (s *podToHost) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	// Construct a unique list of all nodes in the cluster running workloads.

	var addrType string

	for _, pod := range ct.ClientPods() {
		for _, node := range ct.Nodes() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				for _, addr := range node.Status.Addresses {
					if features.GetIPFamily(addr.Address) != ipFam {
						continue
					}

					switch {
					case addr.Type == slimcorev1.NodeInternalIP:
						addrType = "internal-ip"
					case addr.Type == slimcorev1.NodeExternalIP:
						addrType = "external-ip"
					case addr.Type == slimcorev1.NodeHostName:
						addrType = "hostname"
					}

					dst := check.ICMPEndpoint("", addr.Address)
					ipFam := features.GetIPFamily(addr.Address)

					t.NewAction(s, fmt.Sprintf("ping-%s-%s", ipFam, addrType), &pod, dst, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))

						a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
							Protocol: check.ICMP,
						}))

						a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
					})
				}
			})
		}
	}
}

// PodToControlPlaneHost sends an ICMP ping from the controlPlaneclient Pod to all nodes
// in the test context.
func PodToControlPlaneHost() check.Scenario {
	return &podToControlPlaneHost{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToHost implements a Scenario.
type podToControlPlaneHost struct {
	check.ScenarioBase
}

func (s *podToControlPlaneHost) Name() string {
	return "pod-to-controlplane-host"
}

func (s *podToControlPlaneHost) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	for _, pod := range ct.ControlPlaneClientPods() {
		for _, node := range ct.ControlPlaneNodes() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				for _, addr := range node.Status.Addresses {
					if features.GetIPFamily(addr.Address) != ipFam {
						continue
					}
					dst := check.ICMPEndpoint("", addr.Address)
					ipFam := features.GetIPFamily(addr.Address)

					t.NewAction(s, fmt.Sprintf("ping-%s-node-%s-from-pod-%s", ipFam, node.Name, pod.Name()), &pod, dst, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))

						a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
							Protocol: check.ICMP,
						}))

						a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
					})
				}
			})
		}
	}
}

// PodToHostPort sends an HTTP request from all client Pods
// to all echo Services' HostPorts.
func PodToHostPort() check.Scenario {
	return &podToHostPort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToHostPort implements a ConditionalScenario.
type podToHostPort struct {
	check.ScenarioBase
}

func (s *podToHostPort) Name() string {
	return "pod-to-hostport"
}

func (s *podToHostPort) Requirements() []features.Requirement {
	return []features.Requirement{
		features.RequireEnabled(features.HostPort),
	}
}

func (s *podToHostPort) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		for _, echo := range ct.EchoPods() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				hostIP, err := ct.GetPodHostIPByFamily(echo, ipFam)
				if err != nil {
					return
				}
				baseURL := fmt.Sprintf("%s://%s%s", echo.Scheme(), net.JoinHostPort(hostIP, strconv.Itoa(ct.Params().EchoServerHostPort)), echo.Path())
				ep := check.HTTPEndpoint(echo.Name(), baseURL)
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, ep, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(ep))

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{
						// Because the HostPort request is NATed, we might only
						// observe flows after DNAT has been applied (e.g. by
						// HostReachableServices),
						AltDstIP:   echo.Address(ipFam),
						AltDstPort: echo.Port(),
					}))
				})
			})

			i++
		}
	}
}

// HostToPod generates one HTTP request from each node inside the cluster to
// each echo (server) pod in the test context.
func HostToPod() check.Scenario {
	return &hostToPod{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type hostToPod struct {
	check.ScenarioBase
}

func (s *hostToPod) Name() string {
	return "host-to-pod"
}

func (s *hostToPod) RequiresHostNetNSDaemonSet() {}

func (s *hostToPod) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, src := range ct.HostNetNSPodsByNode() {
		if src.Outside {
			continue
		}

		for _, dst := range ct.EchoPods() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &src, dst, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(dst))
				})
			})

			i++
		}
	}
}

// HostToWorld sends multiple HTTP requests to ExternalTarget
// from each node inside the cluster.
func HostToWorld() check.Scenario {
	return &hostToWorld{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// hostToWorld implements a Scenario.
type hostToWorld struct {
	check.ScenarioBase
}

func (s *hostToWorld) Name() string {
	return "host-to-world"
}

func (s *hostToWorld) RequiresHostNetNSDaemonSet() {}

func (s *hostToWorld) Run(ctx context.Context, t *check.Test) {
	extTarget := t.Context().Params().ExternalTarget
	extOtherTarget := t.Context().Params().ExternalOtherTarget
	http := check.HTTPEndpoint(extTarget+"-http", "http://"+extTarget)
	httpOther := check.HTTPEndpoint(extOtherTarget+"-http", "http://"+extOtherTarget)

	var i int
	ct := t.Context()

	for _, src := range ct.HostNetNSPodsByNode() {
		if src.Outside {
			continue
		}

		t.ForEachIPFamily(func(ipFam features.IPFamily) {
			if ipFam == features.IPFamilyV6 && !t.Context().Params().ExternalTargetIPv6Capable {
				return
			}

			// With http, over port 80.
			t.NewAction(s, fmt.Sprintf("http-to-%s-%d", extTarget, i), &src, http, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(http, ipFam, true, nil))
			})

			// With http, over port 80.
			t.NewAction(s, fmt.Sprintf("http-to-%s-%d", extOtherTarget, i), &src, httpOther, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(httpOther, ipFam, true, nil))
			})

			i++
		})
	}
}

// HostPortConflictPort is kubelet's default secure port, which is expected to
// be listening in virtually all deployments.
const HostPortConflictPort = 10250

// HostPortConflict checks that CNI rejects a HostPort already used by kubelet.
func HostPortConflict() check.Scenario {
	return &hostPortConflict{ScenarioBase: check.NewScenarioBase()}
}

type hostPortConflict struct{ check.ScenarioBase }

func (s *hostPortConflict) Name() string { return "hostport-cni-conflict" }

// HostPortListenerAvailable reports whether a node has kubelet's port open.
func HostPortListenerAvailable(ctx context.Context, ct *check.ConnectivityTest) bool {
	for nodeName := range ct.CiliumPods() {
		if hostPortListenerAvailableOnNode(ctx, ct, nodeName) {
			return true
		}
	}
	return false
}

func hostPortListenerAvailableOnNode(ctx context.Context, ct *check.ConnectivityTest, nodeName string) bool {
	ciliumPod, ok := ct.CiliumPods()[nodeName]
	if !ok {
		return false
	}
	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Namespace(), ciliumPod.NameWithoutNamespace(), defaults.AgentContainerName,
		[]string{"cilium-dbg", "shell", "--", "cat", "/proc/net/tcp", "/proc/net/tcp6"})
	if err != nil {
		return false
	}
	return hasWildcardTCPListener(stdout.String(), HostPortConflictPort)
}

func hasWildcardTCPListener(table string, port int) bool {
	wantedPort := fmt.Sprintf("%04X", port)
	for line := range strings.SplitSeq(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		localAddress := strings.Split(fields[1], ":")
		if len(localAddress) == 2 &&
			(localAddress[0] == "00000000" || localAddress[0] == strings.Repeat("0", 32)) &&
			localAddress[1] == wantedPort {
			return true
		}
	}
	return false
}

func (s *hostPortConflict) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	const port = HostPortConflictPort
	for node, ciliumPod := range ct.CiliumPods() {
		if !hostPortListenerAvailableOnNode(ctx, ct, node) {
			continue
		}

		client := ciliumPod.K8sClient
		nodeName := ciliumPod.NodeName()
		name := fmt.Sprintf("hostport-conflict-%s", strings.ToLower(strings.ReplaceAll(nodeName, ".", "-")))
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ct.Params().TestNamespace}, Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{{
				Name:    "pause",
				Image:   ct.Params().CurlImage,
				Command: []string{"/usr/bin/pause"},
				Ports:   []corev1.ContainerPort{{Name: "hostport", ContainerPort: 8080, HostPort: port, Protocol: corev1.ProtocolTCP}},
			}},
		}}
		_, err := client.CreatePod(ctx, pod.Namespace, pod, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("creating hostPort conflict pod on %s: %s", nodeName, err)
			return
		}
		defer client.DeletePod(context.Background(), pod.Namespace, pod.Name, metav1.DeleteOptions{})
		t.Infof("Created pod %s on %s requesting occupied TCP hostPort %d; waiting for CNI rejection", pod.Name, nodeName, port)

		var lastStatus string
		err = wait.PollUntilContextTimeout(ctx, time.Second, 15*time.Second, true, func(ctx context.Context) (bool, error) {
			events, err := client.Clientset.CoreV1().
				Events(pod.Namespace).
				List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("involvedObject.name", pod.Name).String()})
			if err != nil {
				return false, err
			}
			var messages []string
			for _, event := range events.Items {
				messages = append(messages, fmt.Sprintf("%s: %s", event.Reason, event.Message))
				if strings.Contains(event.Message, fmt.Sprintf("hostPort tcp/%d is already in use", port)) {
					return true, nil
				}
			}
			current, err := client.GetPod(ctx, pod.Namespace, pod.Name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					lastStatus = fmt.Sprintf("pod not found; events=%q", messages)
					return false, nil
				}
				return false, err
			}
			lastStatus = fmt.Sprintf("phase=%s events=%q", current.Status.Phase, messages)
			if current.Status.Phase == corev1.PodRunning {
				return false, fmt.Errorf("pod started despite TCP/%d being occupied on %s", port, nodeName)
			}
			return false, nil
		})
		if err != nil {
			t.Fatalf("expected CNI hostPort conflict on node %s: %s (last observed state: %s)", nodeName, err, lastStatus)
			return
		}
		t.Infof("CNI rejected hostPort TCP/%d on node %s because it is already in use", port, nodeName)
		return
	}
	t.Fatalf("no node has TCP/%d listening on a wildcard address", port)
}
