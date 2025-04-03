// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

const (
	HdrSizeICMPEcho = 8
	HdrSizeIPv4     = 20
	HdrSizeIPv6     = 40
)

// PodToPod generates one HTTP request from each client pod
// to each echo (server) pod in the test context. The remote Pod is contacted
// directly, no DNS is involved.
func PodToPod(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToPod{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
	}
}

// podToPod implements a Scenario.
type podToPod struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
}

func (s *podToPod) Name() string {
	return "pod-to-pod"
}

func (s *podToPod) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		if !hasAllLabels(client, s.sourceLabels) {
			continue
		}
		for _, echo := range ct.EchoPods() {
			if !hasAllLabels(echo, s.destinationLabels) {
				continue
			}
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
					if s.method == "" {
						a.ExecInPod(ctx, a.CurlCommand(echo))
					} else {
						a.ExecInPod(ctx, a.CurlCommand(echo, "-X", s.method))
					}

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
					a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))

					a.ValidateMetrics(ctx, echo, a.GetIngressMetricsRequirements())
					a.ValidateMetrics(ctx, echo, a.GetEgressMetricsRequirements())
				})
			})

			i++
		}
	}
}

func PodToPodWithEndpoints(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}

	rc := &retryCondition{}
	for _, opt := range options.retryCondition {
		opt(rc)
	}
	return &podToPodWithEndpoints{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
		path:              options.path,
		retryCondition:    rc,
	}
}

// podToPodWithEndpoints implements a Scenario.
type podToPodWithEndpoints struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
	path              string
	retryCondition    *retryCondition
}

func (s *podToPodWithEndpoints) Name() string {
	return "pod-to-pod-with-endpoints"
}

func (s *podToPodWithEndpoints) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		if !hasAllLabels(client, s.sourceLabels) {
			continue
		}
		for _, echo := range ct.EchoPods() {
			if !hasAllLabels(echo, s.destinationLabels) {
				continue
			}

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				s.curlEndpoints(ctx, t, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, echo, ipFam)
			})

			i++
		}
	}
}

func (s *podToPodWithEndpoints) curlEndpoints(ctx context.Context, t *check.Test, name string,
	client *check.Pod, echo check.TestPeer, ipFam features.IPFamily) {
	ct := t.Context()
	baseURL := fmt.Sprintf("%s://%s:%d", echo.Scheme(), echo.Address(ipFam), echo.Port())
	var curlOpts []string
	if s.method != "" {
		curlOpts = append(curlOpts, "-X", s.method)
	}

	// Manually construct an HTTP endpoint for each API endpoint.
	paths := []string{"public", "private"}
	if s.path != "" { // Override default paths if one is set
		paths = []string{s.path}
	}

	for _, path := range paths {
		epName := fmt.Sprintf("%s-%s", name, path)
		url := fmt.Sprintf("%s/%s", baseURL, path)
		ep := check.HTTPEndpointWithLabels(epName, url, echo.Labels())

		t.NewAction(s, epName, client, ep, ipFam).Run(func(a *check.Action) {
			curlOpts = append(curlOpts, s.retryCondition.CurlOptions(ep, ipFam, *client, ct.Params())...)
			a.ExecInPod(ctx, a.CurlCommand(ep, curlOpts...))

			a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
			a.ValidateFlows(ctx, ep, a.GetIngressRequirements(check.FlowParameters{}))
		})

		// Additionally test private endpoint access with HTTP header expected by policy.
		if path == "private" {
			epName += "with-header"
			labels := echo.Labels()
			labels["X-Very-Secret-Token"] = "42"
			ep = check.HTTPEndpointWithLabels(epName, url, labels)
			t.NewAction(s, epName, client, ep, ipFam).Run(func(a *check.Action) {
				opts := make([]string, 0, len(curlOpts)+2)
				opts = append(opts, curlOpts...)
				opts = append(opts, "-H", "X-Very-Secret-Token: 42")

				a.ExecInPod(ctx, a.CurlCommand(ep, opts...))

				a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
				a.ValidateFlows(ctx, ep, a.GetIngressRequirements(check.FlowParameters{}))
			})
		}
	}
}

// PodToPodNoFrag is a test to check whether a correct MTU is set
// for pods. The check is performed by sending an ICMP Echo request with DF
// set ("do not fragment"). The ICMP payload size of the request:
//
// - For IPv4: $POD_MTU - 20 (IPv4 hdr) - 8 (ICMP Echo hdr)
// - For IPv6: $POD_MTU - 40 (IPv6 hdr) - 8 (ICMP Echo hdr)
func PodToPodNoFrag() check.Scenario {
	return &podToPodNoFrag{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPodNoFrag struct {
	check.ScenarioBase
}

func (s *podToPodNoFrag) Name() string {
	return "pod-to-pod-no-frag"
}

func (s *podToPodNoFrag) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	client := ct.RandomClientPod()

	var server check.Pod
	for _, pod := range ct.EchoPods() {
		// Make sure that the server pod is on another node than client
		if pod.Pod.Status.HostIP != client.Pod.Status.HostIP {
			server = pod
			break
		}
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		mtu := s.deriveMTU(ctx, t, ipFam)
		t.NewAction(s, fmt.Sprintf("ping-%s", ipFam), client, server, ipFam).Run(func(a *check.Action) {
			payloadSize := mtu - HdrSizeICMPEcho
			switch ipFam {
			case features.IPFamilyV4:
				payloadSize -= HdrSizeIPv4
			case features.IPFamilyV6:
				payloadSize -= HdrSizeIPv6
			}
			a.ExecInPod(ctx, t.Context().PingCommand(server, ipFam,
				"-M", "do", // DF
				"-s", strconv.Itoa(payloadSize), // payload size
			))
		})

	})
}

func (s *podToPodNoFrag) deriveMTU(ctx context.Context, t *check.Test, ipFam features.IPFamily) int {
	client := t.Context().RandomClientPod()
	var mtu int

	ipFlag := ""
	if ipFam == features.IPFamilyV6 {
		ipFlag = " -6"
	}
	cmd := []string{
		"/bin/sh", "-c",
		fmt.Sprintf("ip%s route show default | grep -oE 'mtu [^ ]*' | cut -d' ' -f2", ipFlag),
	}
	t.Debugf("Running %s", strings.Join(cmd, " "))
	mtuBytes, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace,
		client.Pod.Name, "", cmd)
	if err != nil {
		t.Fatalf("Failed to get route MTU in pod %s: %s", client, err)
	}
	mtuStr := strings.TrimSpace(mtuBytes.String())

	// Derive MTU from pod iface instead
	if mtuStr == "" {
		cmd := []string{
			"/bin/sh", "-c",
			"cat /sys/class/net/eth0/mtu",
		}
		t.Debugf("Running %s", strings.Join(cmd, " "))
		mtuBytes, err = client.K8sClient.ExecInPod(ctx, client.Pod.Namespace,
			client.Pod.Name, "", cmd)
		if err != nil {
			t.Fatalf("Failed to get eth0 MTU in pod %s: %s", client, err)
		}

		mtuStr = strings.TrimSpace(mtuBytes.String())
	}

	mtu, err = strconv.Atoi(mtuStr)
	if err != nil {
		t.Fatalf("Failed to parse MTU %s: %s", mtuStr, err)
	}
	t.Debugf("Derived MTU: %d", mtu)

	return mtu
}

func PodToPodMissingIPCache(opts ...Option) check.Scenario {
	return newPodToPodMissingIPCache(opts...)
}

func PodToPodMissingIPCacheV2(opts ...Option) check.Scenario {
	scenario := newPodToPodMissingIPCache(opts...)
	scenario.removePodCIDREntries = true
	scenario.useExactMatch = true
	return scenario
}

type podToPodMissingIPCache struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string

	removePodCIDREntries bool
	useExactMatch        bool
}

func newPodToPodMissingIPCache(opts ...Option) *podToPodMissingIPCache {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToPodMissingIPCache{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
	}
}

func (s *podToPodMissingIPCache) Name() string {
	return "pod-to-pod-missing-ipcache"
}

func (s *podToPodMissingIPCache) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	// Temporarily delete echo pods entries from ipcache
	for _, echo := range ct.EchoPods() {
		echoIP := echo.Address(features.IPFamilyV4)
		for _, ciliumPod := range ct.CiliumPods() {
			addr, err := netip.ParseAddr(echoIP)
			if err != nil {
				ct.Warnf("invalid pod IP address: %w", err)
				continue
			}

			restore, err := ipcacheDeleteAndRestore(ctx, ct, ciliumPod, netip.PrefixFrom(addr, addr.BitLen()), s.useExactMatch)
			if err != nil {
				ct.Warnf("ipcache ip entries delete and restore failed: %w", err)
				continue
			}
			defer restore()
		}
	}

	// Temporarily delete pod CIDRs entries from ipcache
	if s.removePodCIDREntries {
		for _, ciliumPod := range ct.CiliumPods() {
			prefixes, err := remoteNodesPodCIDRs(ctx, ciliumPod)
			if err != nil {
				ct.Warnf("unable to get remote nodes pod CIDRs: %w", err)
				continue
			}

			for _, prefix := range prefixes {
				restore, err := ipcacheDeleteAndRestore(ctx, ct, ciliumPod, prefix, s.useExactMatch)
				if err != nil {
					ct.Warnf("ipcache pod CIDR entries delete and restore failed: %w", err)
					continue
				}
				defer restore()
			}
		}
	}

	for _, client := range ct.ClientPods() {
		if !hasAllLabels(client, s.sourceLabels) {
			continue
		}
		for _, echo := range ct.EchoPods() {
			if !hasAllLabels(echo, s.destinationLabels) {
				continue
			}

			// Skip if echo pod is on the same node as client
			if echo.Pod.Spec.NodeName == client.Pod.Spec.NodeName {
				continue
			}

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				if ipFam == features.IPFamilyV6 {
					// encryption-strict-mode-cidr only accepts an IPv4 CIDR
					return
				}
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(echo))

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
					a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))

					a.ValidateMetrics(ctx, echo, a.GetIngressMetricsRequirements())
					a.ValidateMetrics(ctx, echo, a.GetEgressMetricsRequirements())
				})
			})

			i++
		}
	}
}

func remoteNodesPodCIDRs(ctx context.Context, ciliumPod check.Pod) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix

	nodeListCmd := []string{"cilium", "node", "list"}
	output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, nodeListCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %q, %w, %q", nodeListCmd, err, output.String())
	}

	// Parse "cilium node list" output
	//
	// Expected format:
	//
	// Name                           IPv4 Address   Endpoint CIDR   IPv6 Address   Endpoint CIDR   Source
	// kind-kind/kind-control-plane   172.18.0.3     10.244.0.0/24   fc00:c111::3                   local
	// kind-kind/kind-worker          172.18.0.2     10.244.1.0/24   fc00:c111::2                   custom-resource
	// kind-kind/kind-worker2         172.18.0.4     10.244.3.0/24   fc00:c111::4                   custom-resource
	// kind-kind/kind-worker3         172.18.0.5     10.244.2.0/24   fc00:c111::5                   custom-resource
	//
	// see cilium-dbg/cmd/node_list.go for more details
	scanner := bufio.NewScanner(&output)
	nLine := 0
	for scanner.Scan() {
		nLine++

		// discard "cilium node list" header
		if nLine == 1 {
			continue
		}

		fields := strings.Fields(scanner.Text())

		// discard local node CIDR
		if source := fields[len(fields)-1]; source == "local" {
			continue
		}

		endpointCIDR := fields[2]
		prefix, err := netip.ParsePrefix(endpointCIDR)
		if err != nil {
			return nil, fmt.Errorf(`failed to get "Endpoint CIDR" from "cilium node list" output: %q, %w`, endpointCIDR, err)
		}

		prefixes = append(prefixes, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan nodes list: %w", err)
	}

	return prefixes, nil
}

var ipcacheGetPat = regexp.MustCompile(`identity=(\d+)\s+encryptkey=(\d+)\s+tunnelendpoint=([^\s]+)`)

// ipcacheDeleteAndRestore removes matching ipcache entry and return a function to revert the deletion.
func ipcacheDeleteAndRestore(
	ctx context.Context, ct *check.ConnectivityTest,
	ciliumPod check.Pod, prefix netip.Prefix, exactMatch bool,
) (func(), error) {
	var lookupCmd []string
	if exactMatch {
		lookupCmd = []string{"cilium", "bpf", "ipcache", "match", prefix.String()}
	} else {
		lookupCmd = []string{"cilium", "bpf", "ipcache", "get", prefix.Addr().String()}
	}

	output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, lookupCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup ipcache entry: %q, %w, %q", lookupCmd, err, output.String())
	}

	matches := ipcacheGetPat.FindStringSubmatch(output.String())
	if matches == nil {
		return nil, fmt.Errorf("failed to find ipcache entry: %q", output.String())
	}
	identity := matches[1]
	encryptkey := matches[2]
	tunnelendpoint := matches[3]

	deleteCmd := []string{"cilium", "bpf", "ipcache", "delete", prefix.String()}
	if output, err = ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, deleteCmd); err != nil {
		return nil, fmt.Errorf("failed to delete IP cache entry: %q, %w, %q", deleteCmd, err, output.String())
	}

	return func() {
		updateCmd := []string{
			"cilium", "bpf", "ipcache", "update", prefix.String(),
			"--tunnelendpoint", tunnelendpoint, "--identity", identity, "--encryptkey", encryptkey,
		}
		output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, updateCmd)
		if err != nil {
			ct.Warnf("failed to restore ipcache entry: %q, %w, %q", updateCmd, err, output.String())
		}
	}, nil
}
