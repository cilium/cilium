// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
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
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
	}
}

// podToPod implements a Scenario.
type podToPod struct {
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
						a.ExecInPod(ctx, ct.CurlCommand(echo, ipFam))
					} else {
						a.ExecInPod(ctx, ct.CurlCommand(echo, ipFam, "-X", s.method))
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
	return &podToPodWithEndpoints{
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
		path:              options.path,
	}
}

// podToPodWithEndpoints implements a Scenario.
type podToPodWithEndpoints struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
	path              string
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
			a.ExecInPod(ctx, ct.CurlCommand(ep, ipFam, curlOpts...))

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

				a.ExecInPod(ctx, ct.CurlCommand(ep, ipFam, opts...))

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
	return &podToPodNoFrag{}
}

type podToPodNoFrag struct{}

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
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
	}
}

type podToPodMissingIPCache struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
}

func (s *podToPodMissingIPCache) Name() string {
	return "pod-to-pod-missing-ipcache"
}

type bpfMap struct {
	ID int `json:"id"`
}

type bpfMapLookup struct {
	Key   []string `json:"key"`
	Value []string `json:"value"`
}

func dropCountByUnencrypted(ctx context.Context, ct *check.ConnectivityTest) (count int, err error) {
	unencryptedCountCmd := []string{
		"/bin/sh", "-c",
		`cilium metrics list -o json | jq '.[] | select((.name == "cilium_drop_count_total") and (.labels.reason | IN("Traffic is unencrypted"))) | .value'`,
	}

	for _, ciliumPod := range ct.CiliumPods() {
		output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, unencryptedCountCmd)
		if err != nil {
			return 0, err
		}
		if output.String() != "" {
			c, err := strconv.Atoi(strings.TrimSpace(output.String()))
			if err != nil {
				return 0, err
			}
			count += c
		}
	}
	return
}

func structToStrSlice(key *ipcachemap.Key) []string {
	ptr := unsafe.Pointer(reflect.ValueOf(key).Pointer())
	size := unsafe.Sizeof(*key)
	byteSlice := make([]string, size)
	for i := 0; i < int(size); i++ {
		byteSlice[i] = fmt.Sprintf("0x%02x", *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))))
	}
	return byteSlice
}

func (s *podToPodMissingIPCache) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	var ciliumPod check.Pod
	for _, pod := range ct.CiliumPods() {
		ciliumPod = pod
		break
	}

	// Collect all cilium_ipcache maps
	ipcaches := []bpfMap{}
	listIPCacheCmd := []string{"bpftool", "--json", "map", "list", "name", "cilium_ipcache"}
	output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, listIPCacheCmd)
	if err != nil {
		ct.Fatalf(`failed to execute "%s" in %s: %v`, listIPCacheCmd, ciliumPod.Pod.Name, err)
	}
	if err = json.Unmarshal(output.Bytes(), &ipcaches); err != nil {
		ct.Fatalf(`failed to unmarshal output "%s": %v`, output, err)
	}

	// Delete echo pods entries from ipcache
	for _, echo := range ct.EchoPods() {
		echoIP := net.ParseIP(echo.Address(features.IPFamilyV4))
		for _, ipcache := range ipcaches {
			ipcacheKey := ipcachemap.NewKey(echoIP, nil, 0)
			ipcacheKeyInStrSlice := structToStrSlice(&ipcacheKey)
			lookupCmd := append(strings.Split(fmt.Sprintf("bpftool --json map lookup id %d key hex", ipcache.ID), " "), ipcacheKeyInStrSlice...)
			updateCmd := append(strings.Split(fmt.Sprintf("bpftool map update id %d key hex", ipcache.ID), " "), ipcacheKeyInStrSlice...)
			deleteCmd := append(strings.Split(fmt.Sprintf("bpftool map delete id %d key hex", ipcache.ID), " "), ipcacheKeyInStrSlice...)

			output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, lookupCmd)
			if err != nil {
				ct.Warnf(`failed to lookup IP cache entry: "%s", %v, "%s"`, lookupCmd, err, output.String())
				continue
			}
			lookup := bpfMapLookup{}
			if err = json.Unmarshal(output.Bytes(), &lookup); err != nil {
				ct.Warnf(`failed to unmarshal output "%s": %v`, output.String(), err)
				continue
			}
			if strings.Join(lookup.Key, " ") != strings.Join(ipcacheKeyInStrSlice, " ") {
				ct.Debugf("ipcache key not found: %s", strings.Join(ipcacheKeyInStrSlice, " "))
				continue
			}

			if output, err = ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, deleteCmd); err != nil {
				ct.Warnf(`failed to delete IP cache entry: "%s", %v, "%s"`, deleteCmd, err, output.String())
				continue
			}

			defer func(updateCmd []string, lookup bpfMapLookup) {
				updateCmd = append(updateCmd, "value", "hex")
				updateCmd = append(updateCmd, lookup.Value...)
				output, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, updateCmd)
				if err != nil {
					ct.Warnf(`failed to restore IP cache entry: "%s", %v, "%s"`, updateCmd, err, output.String())
				}
			}(updateCmd, lookup)
		}
	}

	prevUnencryptedCount, err := dropCountByUnencrypted(ctx, ct)
	if err != nil {
		ct.Fatalf("Failed to get unencrypted drop count: %v", err)
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
					a.ExecInPod(ctx, ct.CurlCommand(echo, ipFam))

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
					a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))

					a.ValidateMetrics(ctx, echo, a.GetIngressMetricsRequirements())
					a.ValidateMetrics(ctx, echo, a.GetEgressMetricsRequirements())
				})
			})

			i++
		}
	}

	unencryptedCount, err := dropCountByUnencrypted(ctx, ct)
	if err != nil {
		ct.Fatalf("Failed to get unencrypted drop count: %v", err)
	}
	if unencryptedCount < prevUnencryptedCount+i {
		ct.Failf("Unexpected number of unencrypted packets dropped: prev=%d now=%d expected>=%d", prevUnencryptedCount, unencryptedCount, prevUnencryptedCount+i)
	}
}
