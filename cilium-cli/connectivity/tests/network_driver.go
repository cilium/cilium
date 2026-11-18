// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
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
	"github.com/cilium/cilium/cilium-cli/utils/features"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	networkDriverName         = "networkdriver.cilium.io"
	networkDriverDummyManager = "dummy"
	networkDriverPoolName     = "network-driver-dummy-pool"
	networkDriverDummyCount   = 8
	networkDriverPollInterval = 5 * time.Second
	networkDriverTimeout      = 5 * time.Minute
	// networkDriverPendingWait is how long a pod that must not start is
	// watched before the test decides it stayed pending.
	networkDriverPendingWait = 30 * time.Second
)

// NetworkDriverScenarios returns the scenarios exercising the network driver with
// the dummy device manager. They need dummy devices to be published already:
// the agent reads its network driver config once, at start, so the cluster
// must be set up with a CiliumNetworkDriverNodeConfig or ClusterConfig that
// enables the dummy manager before the test runs. Each scenario creates its
// own DeviceClass, ResourceClaimTemplates and pods, and removes them.
func NetworkDriverScenarios() []check.Scenario {
	return []check.Scenario{
		&networkDriverDummy{ScenarioBase: check.NewScenarioBase(), name: "pod-interface", run: runNetworkDriverPodInterface},
	}
}

func NetworkDriverSetup(ctx context.Context, t *check.Test, ct *check.ConnectivityTest) error {
	clusterConfig := fmt.Sprintf("clusterconfig-nd-%s", ct.Params().TestNamespace)

	// Create cluster-wide network driver configuration
	cfg := &ciliumv2alpha1.CiliumNetworkDriverClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: clusterConfig},
		Spec: ciliumv2alpha1.CiliumNetworkDriverClusterConfigSpec{
			Spec: ciliumv2alpha1.CiliumNetworkDriverNodeConfigSpec{
				DeviceManagerConfigs: &ciliumv2alpha1.CiliumNetworkDriverDeviceManagerConfig{
					Dummy: &ciliumv2alpha1.DummyDeviceManagerConfig{Enabled: true, Count: networkDriverDummyCount},
				},
				Pools: []ciliumv2alpha1.CiliumNetworkDriverDevicePoolConfig{{
					PoolName: networkDriverPoolName,
					Filter:   &ciliumv2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{networkDriverDummyManager}},
				}},
			},
		},
	}

	client := ct.K8sClient()
	createdConfig, err := client.CiliumClientset.CiliumV2alpha1().
		CiliumNetworkDriverClusterConfigs().Create(ctx, cfg, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating ClusterConfig %s: %w", cfg.Name, err)
	}

	// Each node should have its network driver node config ready
	if err := waitForNetworkDriverNodeConfigs(ctx, ct, createdConfig.Spec.Spec); err != nil {
		return fmt.Errorf("waiting for node configs: %w", err)
	}

	// Each node should have its network driver resource slices ready
	if err := waitForNetworkDriverResourceSlices(ctx, ct); err != nil {
		return fmt.Errorf("waiting for resource slices: %w", err)
	}

	deviceClassName := fmt.Sprintf("deviceclass-nd-%s", ct.Params().TestNamespace)

	// Create the DeviceClass for the network driver dummy devices
	dc := &resourceapi.DeviceClass{
		ObjectMeta: metav1.ObjectMeta{Name: deviceClassName},
		Spec: resourceapi.DeviceClassSpec{
			Selectors: []resourceapi.DeviceSelector{{CEL: &resourceapi.CELDeviceSelector{
				Expression: fmt.Sprintf(`device.driver == %q && device.attributes[%q].deviceManager == %q`,
					networkDriverName, networkDriverName, networkDriverDummyManager),
			}}},
		},
	}

	if _, err := client.Clientset.ResourceV1().DeviceClasses().Create(ctx, dc, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating DeviceClass %s: %w", deviceClassName, err)
	}

	return nil
}

func waitForNetworkDriverNodeConfigs(
	ctx context.Context,
	ct *check.ConnectivityTest,
	want ciliumv2alpha1.CiliumNetworkDriverNodeConfigSpec,
) error {
	return wait.PollUntilContextTimeout(
		ctx,
		networkDriverPollInterval,
		networkDriverTimeout,
		true,
		func(ctx context.Context) (bool, error) {
			configs, err := ct.K8sClient().CiliumClientset.CiliumV2alpha1().
				CiliumNetworkDriverNodeConfigs().List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, nil
			}
			if len(configs.Items) == 0 ||
				len(configs.Items) != len(ct.CiliumNodes()) {
				return false, nil
			}

			// For each node config, check the specs are ok
			for i := range configs.Items {
				if !configs.Items[i].Spec.DeepEqual(&want) {
					return false, fmt.Errorf("node config spec does not match cluster config spec for node %q",
						configs.Items[i].Name)
				}
			}
			return true, nil
		},
	)
}

func waitForNetworkDriverResourceSlices(
	ctx context.Context,
	ct *check.ConnectivityTest,
) error {
	return wait.PollUntilContextTimeout(
		ctx,
		networkDriverPollInterval,
		networkDriverTimeout,
		true,
		func(ctx context.Context) (bool, error) {
			resourceSlices, err := ct.K8sClient().Clientset.ResourceV1().
				ResourceSlices().List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}

			slicePerNode := map[string]resourceapi.ResourceSlice{}
			for _, slice := range resourceSlices.Items {
				spec := slice.Spec
				if spec.Driver != networkDriverName ||
					spec.NodeName == nil {
					continue
				}
				nodeName := *spec.NodeName
				if _, ok := slicePerNode[nodeName]; ok {
					return false, fmt.Errorf("multiple resource slices for node %q", nodeName)
				}
				slicePerNode[nodeName] = slice
			}

			for _, node := range ct.CiliumNodes() {
				rs, ok := slicePerNode[node.Name]
				if !ok {
					ct.Logf("no resource slice found for node %q", node.Name)
					return false, nil
				}
				if node.Name != rs.Spec.Pool.Name {
					ct.Logf("resourceslice pool name (%s) doesn't match node name (%s)", &rs.Spec.Pool.Name, node.Name)
				}
				if len(rs.Spec.Devices) != networkDriverDummyCount {
					ct.Logf("expected %d devices in resource slice for node %q, found %d",
						networkDriverDummyCount, node.Name, len(rs.Spec.Devices))
					return false, nil
				}
			}
			return true, nil
		},
	)
}

type networkDriverDummy struct {
	check.ScenarioBase

	name string
	run  func(ctx context.Context, t *check.Test, env *networkDriverEnv)
}

func (s *networkDriverDummy) Name() string { return "network-driver-dummy-" + s.name }

// Run runs the test scenario. Tests may call t.Fatalf, failing the whole test on
// the first failure encountered.
func (s *networkDriverDummy) Run(ctx context.Context, t *check.Test) {
	env := newNetworkDriverEnv(ctx, t, s.name)
	if env == nil {
		return
	}
	defer env.cleanup()
	s.run(ctx, t, env)
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

	devices map[string][]string  // node name -> dummy devices it publishes
	agents  map[string]check.Pod // node name -> Cilium agent pod

	// ipv4Enabled/ipv6Enabled mirror enable-network-driver-ipv4/ipv6: the
	// address families the driver accepts and reports in claim status.
	ipv4Enabled bool
	ipv6Enabled bool

	created  []func(context.Context) error
	podIndex int
}

// newNetworkDriverEnv collects the dummy devices published in the cluster and creates
// a DeviceClass selecting them. It returns nil (after failing the test) when
// no node publishes dummy devices.
func newNetworkDriverEnv(ctx context.Context, t *check.Test, scenario string) *networkDriverEnv {
	ct := t.Context()
	env := &networkDriverEnv{
		t: t, ct: ct, ns: ct.Params().TestNamespace, prefix: "nd-" + scenario,
		agents: map[string]check.Pod{},
	}

	for _, pod := range ct.CiliumPods() {
		env.agents[pod.NodeName()] = pod
	}

	ip4, ok := ct.Feature(features.IPv4)
	if ok && ip4.Enabled == true {
		env.ipv4Enabled = true
	}

	ip6, ok := ct.Feature(features.IPv6)
	if ok && ip6.Enabled == true {
		env.ipv6Enabled = true
	}

	t.Debugf("Network driver %s: dummy devices %v (ipv4=%t ipv6=%t)",
		networkDriverName, env.devices, env.ipv4Enabled, env.ipv6Enabled)

	return env
}

// cleanup deletes everything the scenario created, newest first, and waits
// for the scenario's pods to be gone so devices are free for the next one.
func (e *networkDriverEnv) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), networkDriverTimeout)
	defer cancel()
	for _, c := range slices.Backward(e.created) {
		if err := c(ctx); err != nil && !k8serrors.IsNotFound(err) {
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

	deviceClassName := fmt.Sprintf("deviceclass-nd-%s", e.ct.Params().TestNamespace)

	var podClaims []corev1.PodResourceClaim
	for i, c := range claims {
		var reqs []resourceapi.DeviceRequest
		for _, r := range c.Requests {
			ex := &resourceapi.ExactDeviceRequest{DeviceClassName: deviceClassName}
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
						Driver:     networkDriverName,
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
				if d.Driver != networkDriverName {
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

// networkDriverAddrs returns, for host index i, one static address per address family
// the driver has enabled, from documentation ranges: subnet 0 is
// 192.0.2.0/24 and 2001:db8::/64, subnet 1 is 198.51.100.0/24 and
// 2001:db8:1::/64.
func (e *networkDriverEnv) networkDriverAddrs(subnet, i int) (v4, v6 string) {
	if e.ipv4Enabled {
		v4 = netip.MustParsePrefix(fmt.Sprintf("%s.%d/24", []string{"192.0.2", "198.51.100"}[subnet], i)).String()
	}

	if e.ipv6Enabled {
		v6 = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::%x/64", subnet, i)).String()
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
