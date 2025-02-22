// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
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
	var mtu int

	cmd := []string{
		"/bin/sh", "-c",
		"ip route show default | grep -oE 'mtu [^ ]*' | cut -d' ' -f2",
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

	var server check.Pod
	for _, pod := range ct.EchoPods() {
		// Make sure that the server pod is on another node than client
		if pod.Pod.Status.HostIP != client.Pod.Status.HostIP {
			server = pod
			break
		}
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
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

func PodToPodMissingIPCache(opts ...Option) check.Scenario {
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

type podToPodMissingIPCache struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
}

func (s *podToPodMissingIPCache) Name() string {
	return "pod-to-pod-missing-ipcache"
}

func (s *podToPodMissingIPCache) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	// Temporarily delete echo pods entries from ipcache
	ipcacheGetPat := regexp.MustCompile(`identity=(\d+)\s+encryptkey=(\d+)\s+tunnelendpoint=([\d\.]+)`)
	for _, echo := range ct.EchoPods() {
		echoIP := echo.Address(features.IPFamilyV4)
		for _, ciliumPod := range ct.CiliumPods() {
			lookupCmd := []string{"cilium", "bpf", "ipcache", "get", echoIP}
			output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, lookupCmd)
			if err != nil {
				ct.Warnf(`failed to lookup IP cache entry: "%s", %v, "%s"`, lookupCmd, err, output.String())
				continue
			}
			matches := ipcacheGetPat.FindStringSubmatch(output.String())
			identity := matches[1]
			encryptkey := matches[2]
			tunnelendpoint := matches[3]

			deleteCmd := []string{"cilium", "bpf", "ipcache", "delete", echoIP + "/32"}
			if output, err = ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, deleteCmd); err != nil {
				ct.Warnf(`failed to delete IP cache entry: "%s", %v, "%s"`, deleteCmd, err, output.String())
				continue
			}

			updateCmd := []string{"cilium", "bpf", "ipcache", "update", echoIP + "/32"}
			updateCmd = append(updateCmd, "--tunnelendpoint", tunnelendpoint, "--identity", identity, "--encryptkey", encryptkey)
			defer func(ciliumPod check.Pod, updateCmd []string) {
				output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, updateCmd)
				if err != nil {
					ct.Warnf(`failed to restore IP cache entry: "%s", %v, "%s"`, updateCmd, err, output.String())
				}
			}(ciliumPod, updateCmd)
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
