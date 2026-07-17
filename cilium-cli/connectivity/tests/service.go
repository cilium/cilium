// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// PodToService sends an HTTP request from all client Pods
// to all Services in the test context.
func PodToService(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToService{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToService implements a Scenario.
type podToService struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToService) Name() string {
	return "pod-to-service"
}

func (s *podToService) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}
		for _, svc := range ct.EchoServices() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}

			t.ForEachIPFamily(func(ipFamily features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFamily, i), &pod, svc, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))

					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						DNSRequired: true,
						AltDstPort:  svc.Port(),
					}))

					a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
				})
			})
			i++
		}
	}
}

// PodToIngress sends an HTTP request from all client Pods
// to all Ingress service in the test context.
func PodToIngress(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToIngress{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToIngress implements a Scenario.
type podToIngress struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToIngress) Name() string {
	return "pod-to-ingress-service"
}

func (s *podToIngress) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}
		for _, svc := range ct.IngressService() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}

			if versioncheck.MustCompile(">=1.17.0")(ct.CiliumVersion) {
				t.ForEachIPFamily(func(ipFam features.IPFamily) {
					t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &pod, svc, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, a.CurlCommand(svc))

						a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
							DNSRequired: true,
							AltDstPort:  svc.Port(),
						}))
					})
				})
			} else {
				t.NewAction(s, fmt.Sprintf("curl-%d", i), &pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))

					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						DNSRequired: true,
						AltDstPort:  svc.Port(),
					}))
				})
			}

			i++
		}
	}
}

// PodToRemoteNodePort sends an HTTP request from all client Pods
// to all echo Services' NodePorts, but only to other nodes.
func PodToRemoteNodePort() check.Scenario {
	return &podToRemoteNodePort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToRemoteNodePort implements a Scenario.
type podToRemoteNodePort struct {
	check.ScenarioBase
}

func (s *podToRemoteNodePort) Name() string {
	return "pod-to-remote-nodeport"
}

func (s *podToRemoteNodePort) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		for _, svc := range t.Context().EchoServices() {
			for _, node := range t.Context().Nodes() {
				remote := true
				for _, addr := range node.Status.Addresses {
					if pod.Pod.Status.HostIP == addr.Address {
						remote = false
						break
					}
				}
				if !remote {
					continue
				}

				// If src and dst pod are running on different nodes,
				// call the Cilium Pod's host IP on the service's NodePort.
				curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, node, true, false)

				i++
			}
		}
	}
}

// PodToLocalNodePort sends an HTTP request from all client Pods
// to all echo Services' NodePorts, but only on the same node as
// the client Pods.
func PodToLocalNodePort() check.Scenario {
	return &podToLocalNodePort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToLocalNodePort implements a Scenario.
type podToLocalNodePort struct {
	check.ScenarioBase
}

func (s *podToLocalNodePort) Name() string {
	return "pod-to-local-nodeport"
}

func (s *podToLocalNodePort) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		for _, svc := range t.Context().EchoServices() {
			for _, node := range t.Context().Nodes() {
				for _, addr := range node.Status.Addresses {
					if pod.Pod.Status.HostIP == addr.Address {
						// If src and dst pod are running on the same node,
						// call the Cilium Pod's host IP on the service's NodePort.
						curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, node, true, false)

						i++
					}
				}
			}
		}
	}
}

func curlNodePort(ctx context.Context, s check.Scenario, t *check.Test,
	name string, pod *check.Pod, svc check.Service, node *slimcorev1.Node,
	validateFlows bool, secondaryNetwork bool) {

	// Get the NodePort allocated to the Service.
	np := uint32(svc.Service.Spec.Ports[0].NodePort)

	addrs := slices.Clone(node.Status.Addresses)

	if secondaryNetwork {
		if t.Context().Features[features.IPv4].Enabled {
			addrs = append(addrs, slimcorev1.NodeAddress{
				Type:    "SecondaryNetworkIPv4",
				Address: t.Context().SecondaryNetworkNodeIPv4()[node.Name],
			})
		}
		if t.Context().Features[features.IPv6].Enabled {
			addrs = append(addrs, slimcorev1.NodeAddress{
				Type:    "SecondaryNetworkIPv6",
				Address: t.Context().SecondaryNetworkNodeIPv6()[node.Name],
			})
		}
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {

		for _, addr := range addrs {
			if features.GetIPFamily(addr.Address) != ipFam {
				continue
			}

			// On GKE ExternalIP is not reachable from inside a cluster
			if addr.Type == slimcorev1.NodeExternalIP {
				if f, ok := t.Context().Feature(features.Flavor); ok && f.Enabled && f.Mode == "gke" {
					continue
				}
			}

			// Manually construct an HTTP endpoint to override the destination IP
			// and port of the request.
			ep := check.HTTPEndpoint(name, fmt.Sprintf("%s://%s%s", svc.Scheme(), net.JoinHostPort(addr.Address, strconv.FormatUint(uint64(np), 10)), svc.Path()))

			// Create the Action with the original svc as this will influence what the
			// flow matcher looks for in the flow logs.
			t.NewAction(s, name, pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommand(ep))

				if validateFlows {
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						// The fact that curl is hitting the NodePort instead of the
						// backend Pod's port is specified here. This will cause the matcher
						// to accept both the NodePort and the ClusterIP (container) port.
						AltDstPort: np,
					}))
				}

				// On the EKS + IPsec + kube-proxy datapath, an
				// external(host-netns)->NodePort SYN/SYN-ACK is occasionally
				// lost on the masquerade+encrypt+multi-ENI return path and the
				// curl times out (exit 28). kube-proxy's SNAT/masquerade
				// rewrites the tuple before it reaches any Cilium datapath prog,
				// so the connection is invisible to both Hubble and Cilium's BPF
				// conntrack (see the validateFlows note above); a plain sysdump
				// cannot pin the loss. On failure only, take a targeted host
				// capture on the target node's NICs so the next occurrence shows
				// whether the DNAT'd SYN reached the backend and whether the
				// SYN-ACK egressed encrypted toward the external node. This is
				// purely diagnostic and never changes the verdict, so a genuine
				// N/S LB regression still surfaces as exit 28.
				if a.Failed() {
					captureNodePortFailure(ctx, t, a, pod, node, addr.Address, np, svc)
				}
			})
		}
	})
}

// captureNodePortFailure records datapath state on the target node after an
// external(host-netns)->NodePort curl has already failed, so a transient
// EKS + IPsec + kube-proxy N/S LB loss becomes diagnosable on the next run.
//
// It only runs when NodeWithoutCilium, IPsec and kube-proxy (KPR disabled) are
// all in effect: that is the exact datapath where kube-proxy DNATs and
// masquerades the NodePort SYN (making the tuple invisible to Hubble and
// Cilium's BPF conntrack) and the reply must traverse the IPsec encrypt policy
// and per-ENI source routing back to the external node. On any other datapath
// this is a no-op.
//
// The capture is purely diagnostic: it starts short per-NIC host tcpdumps on
// the target node, replays a burst of probes from the external client to try to
// catch a transient recurrence within the capture window, and logs whatever was
// seen. It never calls Fail/Fatal, so the original exit-28 verdict is left
// untouched and a genuine regression still surfaces.
func captureNodePortFailure(ctx context.Context, t *check.Test, a *check.Action,
	client *check.Pod, node *slimcorev1.Node,
	addr string, np uint32, svc check.Service) {

	ipsec, ok := t.Context().Feature(features.IPsecEnabled)
	if !ok || !ipsec.Enabled {
		return
	}
	if kpr, ok := t.Context().Feature(features.KPR); ok && kpr.Enabled {
		// With KPR enabled Cilium does the N/S LB and the tuple is visible to
		// the BPF conntrack / Hubble already; this capture targets the
		// kube-proxy masquerade path specifically.
		return
	}
	if nwc, ok := t.Context().Feature(features.NodeWithoutCilium); !ok || !nwc.Enabled {
		return
	}

	// The host-netns pod on the target node gives us a NET_RAW-capable
	// host-network shell to run tcpdump in.
	target, ok := t.Context().HostNetNSPodsByNode()[node.Name]
	if !ok {
		t.Debugf("No host-netns pod on target node %s, skipping NodePort failure capture", node.Name)
		return
	}

	ifaces := hostPhysicalIfaces(ctx, t, &target)
	if len(ifaces) == 0 {
		t.Debugf("No physical interfaces found on target node %s, skipping NodePort failure capture", node.Name)
		return
	}

	// Match the NodePort, the backend port (the DNAT target) and ESP (the
	// encrypted reply toward the external node). This shows whether the DNAT'd
	// SYN reached the backend and whether the SYN-ACK egressed encrypted.
	backendPort := svc.Port()
	filter := fmt.Sprintf("tcp port %d or tcp port %d or esp", np, backendPort)

	t.Infof("outside-to-nodeport failed on the EKS+IPsec+kube-proxy path; capturing %q on %s (%v) to diagnose the masquerade+encrypt+multi-ENI return path",
		filter, node.Name, ifaces)

	var sniffers []*sniff.Sniffer
	for _, iface := range ifaces {
		name := fmt.Sprintf("%s-%s-%s", a.Name(), node.Name, iface)
		sniffer, cancel, err := sniff.Sniff(ctx, name, &target, iface, filter, sniff.ModeDebug, sniff.SniffKillTimeout, t)
		if err != nil {
			t.Infof("Failed to start diagnostic capture on %s (%s): %s", node.Name, iface, err)
			continue
		}
		defer func(iface string) {
			if err := cancel(); err != nil {
				t.Debugf("Failed to finalize diagnostic capture on %s (%s): %s", node.Name, iface, err)
			}
		}(iface)
		sniffers = append(sniffers, sniffer)
	}
	if len(sniffers) == 0 {
		return
	}

	// Replay a short burst of probes from the external client to try to catch a
	// transient recurrence while the capture is running. This is diagnostic
	// only: the result is intentionally ignored and never touches the verdict.
	// Bound the burst well under sniff.SniffKillTimeout: 8 probes capped at 3s
	// each is at most ~24s, so the capture is still running when we dump it.
	url := fmt.Sprintf("%s://%s%s", svc.Scheme(), net.JoinHostPort(addr, strconv.FormatUint(uint64(np), 10)), svc.Path())
	probe := []string{"/bin/sh", "-c", fmt.Sprintf(
		"for i in $(seq 1 8); do curl --silent --show-error --output /dev/null --connect-timeout 2 --max-time 3 %q || true; done", url)}
	if _, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Spec.Containers[0].Name, probe); err != nil {
		t.Debugf("Diagnostic NodePort probe from %s returned: %s", client.Name(), err)
	}

	for _, sniffer := range sniffers {
		sniffer.Dump(a, "target-node-nic")
	}
}

// hostPhysicalIfaces returns the physical network interfaces of the node the
// given host-netns pod runs on, skipping loopback and virtual/Cilium-managed
// devices that are not relevant to the external return path.
func hostPhysicalIfaces(ctx context.Context, t *check.Test, pod *check.Pod) []string {
	cmd := []string{"/bin/sh", "-c", "ls -1 /sys/class/net"}
	out, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Spec.Containers[0].Name, cmd)
	if err != nil {
		t.Debugf("Failed to list interfaces on %s: %s", pod.NodeName(), err)
		return nil
	}

	skipPrefixes := []string{"lo", "cilium", "lxc", "veth", "docker", "cni", "kube-ipvs", "nodelocaldns", "ip6tnl", "tunl", "sit", "gre", "erspan", "dummy"}
	var ifaces []string
	for iface := range strings.FieldsSeq(out.String()) {
		skip := false
		for _, p := range skipPrefixes {
			if strings.HasPrefix(iface, p) {
				skip = true
				break
			}
		}
		if !skip {
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces
}

// OutsideToNodePort sends an HTTP request from client pod running on a node w/o
// Cilium to NodePort services.
func OutsideToNodePort() check.Scenario {
	return &outsideToNodePort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type outsideToNodePort struct {
	check.ScenarioBase
}

func (s *outsideToNodePort) Name() string {
	return "outside-to-nodeport"
}

func (s *outsideToNodePort) Run(ctx context.Context, t *check.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	// With kube-proxy doing N/S LB it is not possible to see the original client
	// IP, as iptables rules do the LB SNAT/DNAT before the packet hits any
	// of Cilium's datapath BPF progs. So, skip the flow validation in that case.
	status, ok := t.Context().Feature(features.KPR)
	validateFlows := ok && status.Enabled

	for _, svc := range t.Context().EchoServices() {
		for _, node := range t.Context().Nodes() {
			curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &clientPod, svc, node, validateFlows, t.Context().Params().SecondaryNetworkIface != "")
			i++
		}
	}
}

// OutsideToIngressService sends an HTTP request from client pod running on a node w/o
// Cilium to NodePort services.
func OutsideToIngressService() check.Scenario {
	return &outsideToIngressService{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type outsideToIngressService struct {
	check.ScenarioBase
}

func (s *outsideToIngressService) Name() string {
	return "outside-to-ingress-service"
}

func (s *outsideToIngressService) Run(ctx context.Context, t *check.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	for _, svc := range t.Context().IngressService() {
		t.NewAction(s, fmt.Sprintf("curl-ingress-service-%d", i), &clientPod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
			for _, node := range t.Context().Nodes() {
				a.ExecInPod(ctx, a.CurlCommand(svc.ToNodeportService(node)))

				a.ValidateFlows(ctx, clientPod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: true,
					AltDstPort:  svc.Port(),
				}))
			}
		})
		i++
	}
}

// PodToL7Service sends an HTTP request from a given client Pods
// to all L7 LB service in the test context.
func PodToL7Service(name string, clients map[string]check.Pod, opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToL7Service{
		ScenarioBase:      check.NewScenarioBase(),
		name:              name,
		clients:           clients,
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToL7Service implements a Scenario.
type podToL7Service struct {
	check.ScenarioBase

	name              string
	clients           map[string]check.Pod
	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToL7Service) Name() string {
	if len(s.name) == 0 {
		return "pod-to-l7-lb-service"
	}
	return fmt.Sprintf("pod-to-l7-lb-service-%s", s.name)
}

func (s *podToL7Service) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range s.clients {
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}

		for _, svc := range ct.L7LBService() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}
			t.ForEachIPFamily(func(ipFamily features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFamily, i), &pod, svc, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						DNSRequired: true,
						AltDstPort:  svc.Port(),
					}))
				})
			})
			i++
		}
	}
}

// PodToItselfViaService sends an HTTP request from the client pod
// to the ClusterIP services of that pod in the test context
// to confirm hairpinning works.
func PodToItselfViaService() check.Scenario {
	return &podToItselfViaService{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToItselfViaService struct {
	check.ScenarioBase
}

func (s *podToItselfViaService) Name() string {
	return "pod-to-itself-via-service"
}

func (s *podToItselfViaService) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.L7LBClientPods() {
		for _, svc := range ct.L7LBNonL7Service() {
			t.ForEachIPFamily(func(ipFamily features.IPFamily) {
				// Skip IPv6 for versions < 1.19.0
				if ipFamily == features.IPFamilyV6 && !versioncheck.MustCompile(">=1.19.0")(ct.CiliumVersion) {
					return
				}

				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFamily, i), &pod, svc, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						DNSRequired: true,
						AltDstPort:  svc.Port(),
					}))
					a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
				})
			})
			i++
		}
	}

}
