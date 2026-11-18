// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	networkDriverDummyManager = "dummy"
	networkDriverPollInterval = 2 * time.Second
	networkDriverTimeout      = 2 * time.Minute
	// networkDriverPendingWait is how long a pod that must not start is
	// watched before the test decides it stayed pending.
	networkDriverPendingWait = 20 * time.Second
)

// NetworkDriverDummy returns the scenarios exercising the network driver with
// the dummy device manager. They need dummy devices to be published already:
// the agent reads its network driver config once, at start, so the cluster
// must be set up with a CiliumNetworkDriverNodeConfig or ClusterConfig that
// enables the dummy manager before the test runs. Each scenario creates its
// own DeviceClass, ResourceClaimTemplates and pods, and removes them.
func NetworkDriverDummy() []check.Scenario {
	return []check.Scenario{
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "cluster-config-node-selector", run: runNetworkDriverClusterConfigNodeSelector},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "pod-interface", run: runNetworkDriverPodInterface},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "dual-stack", run: runNetworkDriverDualStack},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "ipv4-disabled", run: runNetworkDriverIpv4Disabled},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "ipv6-disabled", run: runNetworkDriverIpv6Disabled},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "interface-sysctl", run: runNetworkDriverInterfaceSysctl},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "invalid-pod-ifname", run: runNetworkDriverInvalidPodIfName},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "multiple-claims", run: runNetworkDriverMultipleClaims},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "multiple-requests", run: runNetworkDriverMultipleRequests},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "request-count", run: runNetworkDriverRequestCount},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "duplicate-pod-ifname", run: runNetworkDriverDuplicatePodIfName},
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "pool-exhaustion-and-reuse", run: runNetworkDriverPoolExhaustion},
	}
}

type networkDriverDummy struct {
	check.ScenarioBase

	name string
	run  func(ctx context.Context, t *check.Test, env *networkDriverEnv)
}

func (s *networkDriverDummy) Name() string { return "network-driver-dummy-" + s.name }

// Run runs the scenario in its own goroutine. t.Fatalf ends the calling
// goroutine with runtime.Goexit, so a failing scenario stops itself and is
// reported, while the next scenarios of the test still run.
func (s *networkDriverDummy) Run(ctx context.Context, t *check.Test) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		env := newNetworkDriverEnv(ctx, t, s.name)
		if env == nil {
			return
		}
		defer env.cleanup()
		s.run(ctx, t, env)
	}()
	<-done
}

// networkDriverEnv is one scenario's view of the cluster: the dummy devices each node
// publishes, the agents to inspect those nodes with, and the objects the
// scenario created. No node is chosen up front: pods only claim devices and
// the scheduler places them on a node that publishes enough of them.
type networkDriverEnv struct {
	t      *check.Test
	ct     *check.ConnectivityTest
	ns     string
	prefix string

	driver  string
	devices map[string][]string  // node name -> dummy devices it publishes
	agents  map[string]check.Pod // node name -> Cilium agent pod

	// ipv4Enabled/ipv6Enabled mirror enable-network-driver-ipv4/ipv6: the
	// address families the driver accepts and reports in claim status.
	ipv4Enabled bool
	ipv6Enabled bool

	class    string
	created  []func(context.Context) error
	podIndex int
}

// newNetworkDriverEnv collects the dummy devices published in the cluster and creates
// a DeviceClass selecting them. It returns nil (after failing the test) when
// no node publishes dummy devices.
func newNetworkDriverEnv(ctx context.Context, t *check.Test, scenario string) *networkDriverEnv {
	ct := t.Context()
	client := ct.K8sClient()
	env := &networkDriverEnv{
		t: t, ct: ct, ns: ct.Params().TestNamespace, prefix: "nd-" + scenario,
		agents: map[string]check.Pod{},
	}

	for _, pod := range ct.CiliumPods() {
		env.agents[pod.NodeName()] = pod
	}

	// Slices appear shortly after the agent registers with the kubelet, so
	// poll for a while instead of failing on the first look.
	var lastErr error
	_ = wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, time.Minute, true, func(ctx context.Context) (bool, error) {
		env.devices, env.driver, lastErr = env.publishedDevices(ctx)
		return lastErr == nil && len(env.devices) > 0, nil
	})
	if lastErr != nil {
		t.Fatalf("Listing ResourceSlices: %s", lastErr)
		return nil
	}
	if len(env.devices) == 0 {
		t.Fatalf("No node publishes network driver devices of manager %q. Configure a "+
			"CiliumNetworkDriverClusterConfig with the dummy device manager before running this test.",
			networkDriverDummyManager)
		return nil
	}

	cm, err := client.GetConfigMap(ctx, ct.Params().CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Reading %s: %s", defaults.ConfigMapName, err)
		return nil
	}
	// Defaults match the agent's: IPv4 on, IPv6 off.
	env.ipv4Enabled = cm.Data["enable-network-driver-ipv4"] != "false"
	env.ipv6Enabled = cm.Data["enable-network-driver-ipv6"] == "true"
	t.Debugf("Network driver %s: dummy devices %v (ipv4=%t ipv6=%t)",
		env.driver, env.devices, env.ipv4Enabled, env.ipv6Enabled)

	env.class = fmt.Sprintf("%s-%s", env.prefix, env.ns)
	dc := &resourceapi.DeviceClass{
		ObjectMeta: metav1.ObjectMeta{Name: env.class},
		Spec: resourceapi.DeviceClassSpec{
			Selectors: []resourceapi.DeviceSelector{{CEL: &resourceapi.CELDeviceSelector{
				Expression: fmt.Sprintf(`device.driver == %q && device.attributes[%q].deviceManager == %q`,
					env.driver, env.driver, networkDriverDummyManager),
			}}},
		},
	}
	if _, err := client.Clientset.ResourceV1().DeviceClasses().Create(ctx, dc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Creating DeviceClass %s: %s", env.class, err)
		return nil
	}
	env.created = append(env.created, func(ctx context.Context) error {
		return client.Clientset.ResourceV1().DeviceClasses().Delete(ctx, env.class, metav1.DeleteOptions{})
	})
	return env
}

// publishedDevices returns the dummy devices in ResourceSlices, by node,
// and the driver publishing them.
func (e *networkDriverEnv) publishedDevices(ctx context.Context) (map[string][]string, string, error) {
	rs, err := e.ct.K8sClient().Clientset.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", err
	}
	byNode := map[string][]string{}
	var driver string
	for _, s := range rs.Items {
		if s.Spec.NodeName == nil {
			continue
		}
		for _, d := range s.Spec.Devices {
			if attrString(d.Attributes, "deviceManager") != networkDriverDummyManager {
				continue
			}
			byNode[*s.Spec.NodeName] = append(byNode[*s.Spec.NodeName], d.Name)
			driver = s.Spec.Driver
		}
	}
	for n := range byNode {
		slices.Sort(byNode[n])
	}
	return byNode, driver, nil
}

// totalDevices is the number of dummy devices published in the cluster.
func (e *networkDriverEnv) totalDevices() int {
	n := 0
	for _, d := range e.devices {
		n += len(d)
	}
	return n
}

// cleanup deletes everything the scenario created, newest first, and waits
// for the scenario's pods to be gone so devices are free for the next one.
func (e *networkDriverEnv) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), networkDriverTimeout)
	defer cancel()
	for i := len(e.created) - 1; i >= 0; i-- {
		if err := e.created[i](ctx); err != nil && !k8serrors.IsNotFound(err) {
			e.t.Infof("Network driver cleanup: %s", err)
		}
	}
	if err := e.waitPodsGone(ctx); err != nil {
		e.t.Infof("Network driver cleanup: %s", err)
	}
}

// networkDriverClaim is the opaque config of one device request, as the driver reads it.
type networkDriverClaim struct {
	PodIfName           string            `json:"podIfName,omitempty"`
	IPv4Addr            string            `json:"ipv4Addr,omitempty"`
	IPv6Addr            string            `json:"ipv6Addr,omitempty"`
	InterfaceSysctlIPv4 map[string]string `json:"interfaceSysctlIPv4,omitempty"`
	InterfaceSysctlIPv6 map[string]string `json:"interfaceSysctlIPv6,omitempty"`
}

// networkDriverRequest is one device request of a claim.
type networkDriverRequest struct {
	Name  string
	Count int64 // 0 means one device
}

// networkDriverConfig is one opaque config entry of a claim. Requests empty means the
// config applies to every request of the claim.
type networkDriverConfig struct {
	Requests []string
	Config   networkDriverClaim
}

// networkDriverClaimSpec is one claim of a pod: its requests and their configs.
type networkDriverClaimSpec struct {
	Requests []networkDriverRequest
	Configs  []networkDriverConfig
}

// single returns the claim spec of one request for one device with cfg.
func single(cfg networkDriverClaim) networkDriverClaimSpec {
	return networkDriverClaimSpec{
		Requests: []networkDriverRequest{{Name: "dev"}},
		Configs:  []networkDriverConfig{{Requests: []string{"dev"}, Config: cfg}},
	}
}

// createPod creates a pod with one single-device claim per entry in claims. It returns the pod name.
func (e *networkDriverEnv) createPod(ctx context.Context, claims ...networkDriverClaim) string {
	specs := make([]networkDriverClaimSpec, 0, len(claims))
	for _, c := range claims {
		specs = append(specs, single(c))
	}
	return e.createPodWithClaims(ctx, specs...)
}

// createPodWithClaims creates a pod with one claim, from its own
// ResourceClaimTemplate, per entry in claims. The pod claims
// are named c0, c1, ... It returns the pod name.
func (e *networkDriverEnv) createPodWithClaims(ctx context.Context, claims ...networkDriverClaimSpec) string {
	client := e.ct.K8sClient().Clientset
	e.podIndex++
	name := fmt.Sprintf("%s-%d", e.prefix, e.podIndex)

	var podClaims []corev1.PodResourceClaim
	for i, c := range claims {
		var reqs []resourceapi.DeviceRequest
		for _, r := range c.Requests {
			ex := &resourceapi.ExactDeviceRequest{DeviceClassName: e.class}
			if r.Count > 0 {
				ex.AllocationMode = resourceapi.DeviceAllocationModeExactCount
				ex.Count = r.Count
			}
			reqs = append(reqs, resourceapi.DeviceRequest{Name: r.Name, Exactly: ex})
		}
		var cfgs []resourceapi.DeviceClaimConfiguration
		for _, cfg := range c.Configs {
			raw, err := json.Marshal(cfg.Config)
			if err != nil {
				e.t.Fatalf("Encoding claim config: %s", err)
			}
			cfgs = append(cfgs, resourceapi.DeviceClaimConfiguration{
				Requests: cfg.Requests,
				DeviceConfiguration: resourceapi.DeviceConfiguration{
					Opaque: &resourceapi.OpaqueDeviceConfiguration{
						Driver:     e.driver,
						Parameters: runtime.RawExtension{Raw: raw},
					},
				},
			})
		}
		tmpl := &resourceapi.ResourceClaimTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-c%d", name, i), Namespace: e.ns},
			Spec: resourceapi.ResourceClaimTemplateSpec{Spec: resourceapi.ResourceClaimSpec{
				Devices: resourceapi.DeviceClaim{Requests: reqs, Config: cfgs},
			}},
		}
		if _, err := client.ResourceV1().ResourceClaimTemplates(e.ns).Create(ctx, tmpl, metav1.CreateOptions{}); err != nil {
			e.t.Fatalf("Creating ResourceClaimTemplate %s: %s", tmpl.Name, err)
		}
		tmplName := tmpl.Name
		e.created = append(e.created, func(ctx context.Context) error {
			return client.ResourceV1().ResourceClaimTemplates(e.ns).Delete(ctx, tmplName, metav1.DeleteOptions{})
		})
		podClaims = append(podClaims, corev1.PodResourceClaim{
			Name:                      fmt.Sprintf("c%d", i),
			ResourceClaimTemplateName: ptr.To(tmplName),
		})
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: e.ns,
			Labels:    map[string]string{"app": e.prefix},
		},
		Spec: corev1.PodSpec{
			// No node selection: the scheduler places the pod on a node
			// whose published devices satisfy its claims.
			TerminationGracePeriodSeconds: ptr.To[int64](0),
			Containers: []corev1.Container{{
				Name:    "c",
				Image:   e.ct.Params().CurlImage,
				Command: []string{"sleep", "infinity"},
			}},
			ResourceClaims: podClaims,
		},
	}
	if _, err := client.CoreV1().Pods(e.ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		e.t.Fatalf("Creating pod %s: %s", name, err)
	}
	e.created = append(e.created, func(ctx context.Context) error {
		return client.CoreV1().Pods(e.ns).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	})
	return name
}

// ndDeviceStatus is what the driver is expected to report for one device in
// ResourceClaim.status.devices.
type ndDeviceStatus struct {
	InterfaceName string
	IPs           []string
}

// expectClaimStatus checks the driver's device status entries of the pod
// claim podClaim (c0, c1, ...) match want, in any order. Address families
// the driver has disabled are dropped from want: the driver does not report
// them.
func (e *networkDriverEnv) expectClaimStatus(ctx context.Context, pod, podClaim string, want ...ndDeviceStatus) {
	for i := range want {
		want[i].IPs = slices.DeleteFunc(slices.Clone(want[i].IPs), func(ip string) bool {
			v6 := strings.Contains(ip, ":")
			return (v6 && !e.ipv6Enabled) || (!v6 && !e.ipv4Enabled)
		})
		slices.Sort(want[i].IPs)
	}
	key := func(d ndDeviceStatus) string { return d.InterfaceName + "=" + strings.Join(d.IPs, ",") }
	wantKeys := make([]string, 0, len(want))
	for _, w := range want {
		wantKeys = append(wantKeys, key(w))
	}
	slices.Sort(wantKeys)

	client := e.ct.K8sClient().Clientset
	var got []string
	err := wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			p, err := client.CoreV1().Pods(e.ns).Get(ctx, pod, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			var claimName string
			for _, s := range p.Status.ResourceClaimStatuses {
				if s.Name == podClaim && s.ResourceClaimName != nil {
					claimName = *s.ResourceClaimName
				}
			}
			if claimName == "" {
				return false, nil
			}
			c, err := client.ResourceV1().ResourceClaims(e.ns).Get(ctx, claimName, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			got = got[:0]
			for _, d := range c.Status.Devices {
				if d.Driver != e.driver {
					continue
				}
				st := ndDeviceStatus{}
				if d.NetworkData != nil {
					st.InterfaceName = d.NetworkData.InterfaceName
					st.IPs = slices.Clone(d.NetworkData.IPs)
					slices.Sort(st.IPs)
				}
				got = append(got, key(st))
			}
			slices.Sort(got)
			return slices.Equal(got, wantKeys), nil
		})
	if err != nil {
		e.t.Fatalf("Pod %s claim %s device status = %v, want %v", pod, podClaim, got, wantKeys)
	}
}

// expectPodLink checks the pod has link ifName, up, carrying every address
// in addrs (CIDR notation).
func (e *networkDriverEnv) expectPodLink(ctx context.Context, pod, ifName string, addrs ...string) {
	out, err := e.podExec(ctx, pod, "ip", "addr", "show", "dev", ifName)
	if err != nil {
		e.t.Fatalf("Pod %s has no %s: %s", pod, ifName, err)
	}
	for _, a := range addrs {
		family := "inet "
		if strings.Contains(a, ":") {
			family = "inet6 "
		}
		if !strings.Contains(out, family+a) {
			e.t.Fatalf("Pod %s link %s lacks %s: %s", pod, ifName, a, out)
		}
	}
	state, err := e.podExec(ctx, pod, "cat", "/sys/class/net/"+ifName+"/operstate")
	if err != nil || strings.TrimSpace(state) == "down" {
		e.t.Fatalf("Pod %s link %s not up: %q %v", pod, ifName, state, err)
	}
}

// expectRejected checks the pod never starts and its events carry a
// message containing one of msgs, then deletes it and checks no device is
// left on the host.
func (e *networkDriverEnv) expectRejected(ctx context.Context, pod string, msgs ...string) {
	e.expectPending(ctx, pod)
	err := wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			ev := e.podEvents(ctx, pod)
			for _, m := range msgs {
				if strings.Contains(ev, m) {
					return true, nil
				}
			}
			return false, nil
		})
	if err != nil {
		e.t.Fatalf("Pod %s: no event mentioning any of %q; events: %s", pod, msgs, e.podEvents(ctx, pod))
	}
	e.deletePodCheckHost(ctx, pod)
}

func (e *networkDriverEnv) podPhase(ctx context.Context, name string) corev1.PodPhase {
	p, err := e.ct.K8sClient().Clientset.CoreV1().Pods(e.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return p.Status.Phase
}

func (e *networkDriverEnv) waitRunning(ctx context.Context, name string) {
	err := wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) { return e.podPhase(ctx, name) == corev1.PodRunning, nil })
	if err != nil {
		e.t.Fatalf("Pod %s not Running: %s; events: %s", name, err, e.podEvents(ctx, name))
	}
}

// expectPending checks the pod does not start within networkDriverPendingWait.
func (e *networkDriverEnv) expectPending(ctx context.Context, name string) {
	err := wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverPendingWait, true,
		func(ctx context.Context) (bool, error) { return e.podPhase(ctx, name) == corev1.PodRunning, nil })
	if err == nil {
		e.t.Fatalf("Pod %s is Running, expected it to stay Pending", name)
	}
}

func (e *networkDriverEnv) deletePod(ctx context.Context, name string) {
	err := e.ct.K8sClient().Clientset.CoreV1().Pods(e.ns).Delete(ctx, name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	if err != nil && !k8serrors.IsNotFound(err) {
		e.t.Fatalf("Deleting pod %s: %s", name, err)
	}
	err = wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			_, err := e.ct.K8sClient().Clientset.CoreV1().Pods(e.ns).Get(ctx, name, metav1.GetOptions{})
			return k8serrors.IsNotFound(err), nil
		})
	if err != nil {
		e.t.Fatalf("Pod %s not deleted: %s", name, err)
	}
}

func (e *networkDriverEnv) waitPodsGone(ctx context.Context) error {
	return wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			l, err := e.ct.K8sClient().Clientset.CoreV1().Pods(e.ns).List(ctx,
				metav1.ListOptions{LabelSelector: "app=" + e.prefix})
			return err == nil && len(l.Items) == 0, nil
		})
}

// podEvents returns the events of the pod, one per line, for diagnostics
// and for asserting on prepare errors.
func (e *networkDriverEnv) podEvents(ctx context.Context, name string) string {
	l, err := e.ct.K8sClient().Clientset.CoreV1().Events(e.ns).List(ctx,
		metav1.ListOptions{FieldSelector: "involvedObject.name=" + name})
	if err != nil {
		return fmt.Sprintf("(listing events: %s)", err)
	}
	var out []string
	for _, ev := range l.Items {
		out = append(out, ev.Reason+": "+ev.Message)
	}
	return strings.Join(out, "\n")
}

// podExec runs cmd in the pod's container.
func (e *networkDriverEnv) podExec(ctx context.Context, name string, cmd ...string) (string, error) {
	out, err := e.ct.K8sClient().ExecInPod(ctx, e.ns, name, "c", cmd)
	return out.String(), err
}

// podNode returns the node the pod was scheduled to, or "" if none yet.
func (e *networkDriverEnv) podNode(ctx context.Context, name string) string {
	p, err := e.ct.K8sClient().Clientset.CoreV1().Pods(e.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return p.Spec.NodeName
}

// hostLinks returns the dummy links present in node's host netns, read
// through the node's Cilium agent.
func (e *networkDriverEnv) hostLinks(ctx context.Context, node string) []string {
	agent, ok := e.agents[node]
	if !ok {
		e.t.Fatalf("No Cilium agent on node %s", node)
	}
	out, err := agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name,
		defaults.AgentContainerName, []string{"ip", "-o", "link", "show", "type", "dummy"})
	if err != nil {
		e.t.Fatalf("Listing dummy links on %s: %s", node, err)
	}
	var names []string
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		names = append(names, strings.TrimSuffix(strings.SplitN(f[1], "@", 2)[0], ":"))
	}
	return names
}

// expectDevicesNotOnHost checks none of the dummy devices node publishes is
// left in its host netns: a freed device is either inside a pod netns or
// deleted.
func (e *networkDriverEnv) expectDevicesNotOnHost(ctx context.Context, node string) {
	err := wait.PollUntilContextTimeout(ctx, networkDriverPollInterval, networkDriverTimeout, true,
		func(ctx context.Context) (bool, error) {
			for _, l := range e.hostLinks(ctx, node) {
				if slices.Contains(e.devices[node], l) {
					return false, nil
				}
			}
			return true, nil
		})
	if err != nil {
		e.t.Fatalf("Dummy devices left on host %s: %v", node, e.hostLinks(ctx, node))
	}
}

// deletePodCheckHost deletes the pod and checks the node it ran on has none
// of its dummy devices left in the host netns. A pod that was never
// scheduled has no node to check.
func (e *networkDriverEnv) deletePodCheckHost(ctx context.Context, pod string) {
	node := e.podNode(ctx, pod)
	e.deletePod(ctx, pod)
	if node != "" {
		e.expectDevicesNotOnHost(ctx, node)
	}
}

func attrString(attrs map[resourceapi.QualifiedName]resourceapi.DeviceAttribute, name string) string {
	if a, ok := attrs[resourceapi.QualifiedName(name)]; ok && a.StringValue != nil {
		return *a.StringValue
	}
	return ""
}

// expectSysctls fails the test unless every net.<family>.conf.<ifName>.<key>
// in want has the given value inside pod.
func (e *networkDriverEnv) expectSysctls(ctx context.Context, pod, family, ifName string, want map[string]string) {
	for key, val := range want {
		path := fmt.Sprintf("/proc/sys/net/%s/conf/%s/%s", family, ifName, key)
		out, err := e.podExec(ctx, pod, "cat", path)
		if err != nil {
			e.t.Fatalf("Reading %s in pod %s: %s", path, pod, err)
		}
		if got := strings.TrimSpace(out); got != val {
			e.t.Fatalf("Pod %s %s = %q, want %q", pod, path, got, val)
		}
	}
}

// requireDevices skips the scenario unless some node publishes at least n
// dummy devices: all devices of one pod must come from the same node.
func (e *networkDriverEnv) requireDevices(n int) bool {
	for _, d := range e.devices {
		if len(d) >= n {
			return true
		}
	}
	e.t.Infof("Skipping: no node publishes %d dummy devices: %v", n, e.devices)
	return false
}

// networkDriverAddrs returns, for host index i, one static address per address family
// the driver has enabled, from documentation ranges: subnet 0 is
// 192.0.2.0/24 and 2001:db8::/64, subnet 1 is 198.51.100.0/24 and
// 2001:db8:1::/64.
func (e *networkDriverEnv) networkDriverAddrs(subnet, i int) (v4, v6 string) {
	if e.ipv4Enabled {
		v4 = fmt.Sprintf("%s.%d/24", []string{"192.0.2", "198.51.100"}[subnet], i)
	}
	if e.ipv6Enabled {
		v6 = fmt.Sprintf("2001:db8:%x::%x/64", subnet, i)
	}
	return v4, v6
}

// nonEmpty returns its non-empty arguments.
func nonEmpty(ss ...string) []string {
	return slices.DeleteFunc(ss, func(s string) bool { return s == "" })
}

// runNetworkDriverPodInterface: a claim with podIfName and a static address of each
// enabled family gives the pod a link with that name, up, with the
// addresses, and the claim status reports them. eth0 is untouched. Deleting
// the pod leaves no dummy device on the host.
func runNetworkDriverPodInterface(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	const ifName = "net1"
	v4, v6 := e.networkDriverAddrs(0, 10)
	pod := e.createPod(ctx, networkDriverClaim{PodIfName: ifName, IPv4Addr: v4, IPv6Addr: v6})
	e.waitRunning(ctx, pod)

	e.expectPodLink(ctx, pod, ifName, nonEmpty(v4, v6)...)
	e.expectClaimStatus(ctx, pod, "c0", ndDeviceStatus{InterfaceName: ifName, IPs: nonEmpty(v4, v6)})
	// The pod's own interface from CNI must be untouched.
	if _, err := e.podExec(ctx, pod, "cat", "/sys/class/net/eth0/ifindex"); err != nil {
		t.Fatalf("Pod %s lost eth0: %s", pod, err)
	}

	e.deletePodCheckHost(ctx, pod)
}

// runNetworkDriverDualStack: with both families enabled in the driver, a claim with
// ipv4Addr and ipv6Addr gives the pod link both addresses, the IPv6 one
// usable (not tentative or dadfailed), and the claim status reports both.
// Per-family interface sysctls from the same claim are applied to the link.
func runNetworkDriverDualStack(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if !e.ipv4Enabled || !e.ipv6Enabled {
		t.Infof("Skipping: needs enable-network-driver-ipv4 and -ipv6 on")
		return
	}
	const ifName = "net1"
	addr4, addr6 := e.networkDriverAddrs(0, 20)
	// Values differ from kernel defaults so the check proves they were set.
	sysctl4 := map[string]string{"arp_ignore": "1"}
	sysctl6 := map[string]string{"accept_ra": "0", "accept_dad": "0"}
	pod := e.createPod(ctx, networkDriverClaim{
		PodIfName:           ifName,
		IPv4Addr:            addr4,
		IPv6Addr:            addr6,
		InterfaceSysctlIPv4: sysctl4,
		InterfaceSysctlIPv6: sysctl6,
	})
	e.waitRunning(ctx, pod)

	e.expectPodLink(ctx, pod, ifName, addr4, addr6)
	out, _ := e.podExec(ctx, pod, "ip", "addr", "show", "dev", ifName)
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "inet6 "+addr6) &&
			(strings.Contains(line, "tentative") || strings.Contains(line, "dadfailed")) {
			t.Fatalf("Pod %s address %s not usable: %s", pod, addr6, strings.TrimSpace(line))
		}
	}
	e.expectSysctls(ctx, pod, "ipv4", ifName, sysctl4)
	e.expectSysctls(ctx, pod, "ipv6", ifName, sysctl6)
	e.expectClaimStatus(ctx, pod, "c0", ndDeviceStatus{InterfaceName: ifName, IPs: []string{addr4, addr6}})

	e.deletePodCheckHost(ctx, pod)
}

// runNetworkDriverIpv4Disabled: with IPv4 disabled in the driver, a claim asking for
// an IPv4 address is rejected when it is prepared. Accepting it would
// configure an address the driver does not report in the claim status.
func runNetworkDriverIpv4Disabled(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if e.ipv4Enabled {
		t.Infof("Skipping: enable-network-driver-ipv4 is on")
		return
	}
	pod := e.createPod(ctx, networkDriverClaim{PodIfName: "net1", IPv4Addr: "192.0.2.21/24"})
	e.expectRejected(ctx, pod, "ipv4", "IPv4")
}

// runNetworkDriverIpv6Disabled: with IPv6 disabled in the driver, a claim asking for
// an IPv6 address is rejected when it is prepared. Accepting it would
// configure an address the driver does not report in the claim status.
func runNetworkDriverIpv6Disabled(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if e.ipv6Enabled {
		t.Infof("Skipping: enable-network-driver-ipv6 is on")
		return
	}
	pod := e.createPod(ctx, networkDriverClaim{PodIfName: "net1", IPv6Addr: "2001:db8::21/64"})
	e.expectRejected(ctx, pod, "ipv6", "IPv6")
}

// runNetworkDriverInterfaceSysctl: per-family interface sysctls are applied to the
// link inside the pod netns, for each family the driver has enabled.
func runNetworkDriverInterfaceSysctl(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	const ifName = "net1"
	cfg := e.sysctlConfig()
	cfg.PodIfName = ifName
	pod := e.createPod(ctx, cfg)
	e.waitRunning(ctx, pod)

	e.expectSysctls(ctx, pod, "ipv4", ifName, cfg.InterfaceSysctlIPv4)
	e.expectSysctls(ctx, pod, "ipv6", ifName, cfg.InterfaceSysctlIPv6)
	e.expectClaimStatus(ctx, pod, "c0", ndDeviceStatus{InterfaceName: ifName})
	e.deletePod(ctx, pod)
}

// runNetworkDriverInvalidPodIfName: a reserved podIfName is rejected when the claim is
// prepared, so the pod never starts and no device is left on the host.
func runNetworkDriverInvalidPodIfName(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	pod := e.createPod(ctx, networkDriverClaim{PodIfName: "lo"})
	e.expectRejected(ctx, pod, "is reserved")
}

// runNetworkDriverMultipleClaims: two claims on one pod each get their own device and
// config, and each claim's status reports only its own device.
func runNetworkDriverMultipleClaims(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if !e.requireDevices(2) {
		return
	}
	a4, a6 := e.networkDriverAddrs(0, 31)
	b4, b6 := e.networkDriverAddrs(1, 31)
	pod := e.createPod(ctx,
		networkDriverClaim{PodIfName: "net1", IPv4Addr: a4, IPv6Addr: a6},
		networkDriverClaim{PodIfName: "net2", IPv4Addr: b4, IPv6Addr: b6},
	)
	e.waitRunning(ctx, pod)

	e.expectPodLink(ctx, pod, "net1", nonEmpty(a4, a6)...)
	e.expectPodLink(ctx, pod, "net2", nonEmpty(b4, b6)...)
	e.expectClaimStatus(ctx, pod, "c0", ndDeviceStatus{InterfaceName: "net1", IPs: nonEmpty(a4, a6)})
	e.expectClaimStatus(ctx, pod, "c1", ndDeviceStatus{InterfaceName: "net2", IPs: nonEmpty(b4, b6)})

	e.deletePodCheckHost(ctx, pod)
}

// runNetworkDriverMultipleRequests: one claim with two requests, each with its own
// config, gives each device the config of its request.
func runNetworkDriverMultipleRequests(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if !e.requireDevices(2) {
		return
	}
	a4, a6 := e.networkDriverAddrs(0, 32)
	b4, b6 := e.networkDriverAddrs(1, 32)
	pod := e.createPodWithClaims(ctx, networkDriverClaimSpec{
		Requests: []networkDriverRequest{{Name: "r1"}, {Name: "r2"}},
		Configs: []networkDriverConfig{
			{Requests: []string{"r1"}, Config: networkDriverClaim{PodIfName: "net1", IPv4Addr: a4, IPv6Addr: a6}},
			{Requests: []string{"r2"}, Config: networkDriverClaim{PodIfName: "net2", IPv4Addr: b4, IPv6Addr: b6}},
		},
	})
	e.waitRunning(ctx, pod)

	e.expectPodLink(ctx, pod, "net1", nonEmpty(a4, a6)...)
	e.expectPodLink(ctx, pod, "net2", nonEmpty(b4, b6)...)
	e.expectClaimStatus(ctx, pod, "c0",
		ndDeviceStatus{InterfaceName: "net1", IPs: nonEmpty(a4, a6)},
		ndDeviceStatus{InterfaceName: "net2", IPs: nonEmpty(b4, b6)},
	)

	e.deletePodCheckHost(ctx, pod)
}

// sysctlConfig returns a claim config setting one non-default interface
// sysctl per address family the driver has enabled, and nothing else.
func (e *networkDriverEnv) sysctlConfig() networkDriverClaim {
	var c networkDriverClaim
	if e.ipv4Enabled {
		c.InterfaceSysctlIPv4 = map[string]string{"arp_ignore": "1"}
	}
	if e.ipv6Enabled {
		c.InterfaceSysctlIPv6 = map[string]string{"accept_ra": "0"}
	}
	return c
}

// devicesInPod returns which of the published dummy devices are present,
// under their kernel names, inside the pod.
func (e *networkDriverEnv) devicesInPod(ctx context.Context, pod string) []string {
	out, err := e.podExec(ctx, pod, "ls", "/sys/class/net")
	if err != nil {
		e.t.Fatalf("Listing links in pod %s: %s", pod, err)
	}
	published := e.devices[e.podNode(ctx, pod)]
	var in []string
	for _, l := range strings.Fields(out) {
		if slices.Contains(published, l) {
			in = append(in, l)
		}
	}
	return in
}

// expectKernelNamedDevices checks the pod holds exactly n published dummy
// devices under their kernel names, each with the sysctls in want, and
// that the claim status reports those names.
func (e *networkDriverEnv) expectKernelNamedDevices(ctx context.Context, pod string, n int, want networkDriverClaim) {
	in := e.devicesInPod(ctx, pod)
	if len(in) != n {
		e.t.Fatalf("Pod %s holds dummy devices %v, want %d of %v", pod, in, n, e.devices[e.podNode(ctx, pod)])
	}
	var st []ndDeviceStatus
	for _, l := range in {
		e.expectSysctls(ctx, pod, "ipv4", l, want.InterfaceSysctlIPv4)
		e.expectSysctls(ctx, pod, "ipv6", l, want.InterfaceSysctlIPv6)
		st = append(st, ndDeviceStatus{InterfaceName: l})
	}
	e.expectClaimStatus(ctx, pod, "c0", st...)
}

// runNetworkDriverRequestCount: one request for two devices with no podIfName gives
// the pod both devices under their kernel names, both with the request's
// sysctls.
func runNetworkDriverRequestCount(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if !e.requireDevices(2) {
		return
	}
	want := e.sysctlConfig()
	pod := e.createPodWithClaims(ctx, networkDriverClaimSpec{
		Requests: []networkDriverRequest{{Name: "dev", Count: 2}},
		Configs:  []networkDriverConfig{{Requests: []string{"dev"}, Config: want}},
	})
	e.waitRunning(ctx, pod)
	e.expectKernelNamedDevices(ctx, pod, 2, want)

	e.deletePodCheckHost(ctx, pod)
}

// runNetworkDriverDuplicatePodIfName: two claims of one pod asking for the same
// podIfName are rejected when they are prepared, with an error naming the
// conflict, not when the second rename fails in the pod netns.
func runNetworkDriverDuplicatePodIfName(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	if !e.requireDevices(2) {
		return
	}
	pod := e.createPod(ctx, networkDriverClaim{PodIfName: "net1"}, networkDriverClaim{PodIfName: "net1"})
	e.expectRejected(ctx, pod, "FailedPrepareDynamicResources")
	if ev := e.podEvents(ctx, pod); strings.Contains(ev, "file exists") {
		t.Fatalf("Pod %s: duplicate podIfName only caught by the kernel rename: %s", pod, ev)
	}
}

// runNetworkDriverPoolExhaustion: one pod per node takes all of the node's dummy
// devices with a single request, so every device in the cluster is in use
// whatever the configured count; one more pod stays pending; once one of
// the full pods is deleted, the pending one starts.
func runNetworkDriverPoolExhaustion(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	var pods []string
	for node, devs := range e.devices {
		if len(devs) == 0 {
			continue
		}
		pod := e.createPodWithClaims(ctx, networkDriverClaimSpec{
			Requests: []networkDriverRequest{{Name: "dev", Count: int64(len(devs))}},
		})
		t.Debugf("Pod %s takes all %d dummy devices, expected on node %s", pod, len(devs), node)
		pods = append(pods, pod)
	}
	for _, p := range pods {
		e.waitRunning(ctx, p)
	}

	extra := e.createPod(ctx, networkDriverClaim{PodIfName: "net1"})
	e.expectPending(ctx, extra)

	e.deletePod(ctx, pods[0])
	e.waitRunning(ctx, extra)
	e.expectPodLink(ctx, extra, "net1")
	e.expectClaimStatus(ctx, extra, "c0", ndDeviceStatus{InterfaceName: "net1"})
}

// runNetworkDriverClusterConfigNodeSelector: every node selected by a
// CiliumNetworkDriverClusterConfig enabling the dummy manager gets a
// NodeConfig generated by the operator with that config's spec, and
// publishes exactly that many dummy devices. Nodes no such ClusterConfig
// selects publish none. When several ClusterConfigs select a node, the
// oldest wins, as in the operator.
func runNetworkDriverClusterConfigNodeSelector(ctx context.Context, t *check.Test, e *networkDriverEnv) {
	client := e.ct.K8sClient()
	ccs, err := client.CiliumClientset.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Listing CiliumNetworkDriverClusterConfigs: %s", err)
	}
	if len(ccs.Items) == 0 {
		t.Fatalf("No CiliumNetworkDriverClusterConfig found; this test expects the operator to generate NodeConfigs")
	}
	cfgs := ccs.Items
	slices.SortFunc(cfgs, func(a, b ciliumv2alpha1.CiliumNetworkDriverClusterConfig) int {
		if c := a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})

	nodes, err := client.ListCiliumNodes(ctx)
	if err != nil {
		t.Fatalf("Listing CiliumNodes: %s", err)
	}

	// Expected config per node: the oldest ClusterConfig selecting it.
	want := map[string]*ciliumv2alpha1.CiliumNetworkDriverClusterConfig{}
	for i := range cfgs {
		cc := &cfgs[i]
		sel := slimlabels.Everything()
		if cc.Spec.NodeSelector != nil {
			if sel, err = slimv1.LabelSelectorAsSelector(cc.Spec.NodeSelector); err != nil {
				t.Fatalf("ClusterConfig %s: invalid nodeSelector: %s", cc.Name, err)
			}
		}
		for _, n := range nodes.Items {
			if _, taken := want[n.Name]; !taken && sel.Matches(slimlabels.Set(n.Labels)) {
				want[n.Name] = cc
			}
		}
	}

	ncs, err := client.CiliumClientset.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Listing CiliumNetworkDriverNodeConfigs: %s", err)
	}
	got := map[string]ciliumv2alpha1.CiliumNetworkDriverNodeConfigSpec{}
	for _, nc := range ncs.Items {
		got[nc.Name] = nc.Spec
	}

	selected := 0
	for _, n := range nodes.Items {
		cc, ok := want[n.Name]
		spec, have := got[n.Name]
		switch {
		case !ok && have:
			t.Fatalf("Node %s matches no ClusterConfig but has a NodeConfig", n.Name)
		case !ok:
			if d := e.devices[n.Name]; len(d) != 0 {
				t.Fatalf("Node %s matches no ClusterConfig but publishes dummy devices %v", n.Name, d)
			}
			continue
		case !have:
			t.Fatalf("Node %s matches ClusterConfig %s but has no NodeConfig", n.Name, cc.Name)
		case !spec.DeepEqual(&cc.Spec.Spec):
			t.Fatalf("Node %s NodeConfig differs from ClusterConfig %s", n.Name, cc.Name)
		}

		wantCount := 0
		if dm := cc.Spec.Spec.DeviceManagerConfigs; dm != nil && dm.Dummy != nil && dm.Dummy.Enabled {
			wantCount = dm.Dummy.Count
		}
		if wantCount > 0 {
			selected++
		}
		if d := e.devices[n.Name]; len(d) != wantCount {
			t.Fatalf("Node %s (ClusterConfig %s) publishes dummy devices %v, want %d",
				n.Name, cc.Name, d, wantCount)
		}
	}
	if selected == 0 {
		t.Fatalf("No node selected by a ClusterConfig enabling the dummy manager")
	}
	t.Debugf("ClusterConfig node selection: %d node(s) publish dummy devices %v", selected, e.devices)
}
