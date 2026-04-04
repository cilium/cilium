// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// FQDNRestoreAfterRestart validates that FQDN-based policy enforcement survives
// a Cilium restart.
//
// The test requires ExternalIPv4/ExternalIPv6 and ExternalOtherIPv4/ExternalOtherIPv6
// to be set to the pre-resolved addresses of ExternalTarget and ExternalOtherTarget
// respectively, because the DNS proxy is unavailable during the restart and
// connectivity must be verified by IP only during that window.
//
// The cluster should be deployed with:
//   - dnsProxy.idleConnectionGracePeriod=5m  (keep existing connections alive)
//   - dnsProxy.minTtl=300                    (force long TTLs so IPs are cached)
func FQDNRestoreAfterRestart() check.Scenario {
	return &fqdnRestoreAfterRestart{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type fqdnRestoreAfterRestart struct {
	check.ScenarioBase
}

func (s *fqdnRestoreAfterRestart) Name() string {
	return "seq-fqdn-restore-after-restart"
}

func (s *fqdnRestoreAfterRestart) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	params := ct.Params()

	client := ct.RandomClientPod()
	if client == nil {
		t.Fatalf("No client pod available")
	}

	// FQDN identities are node-local (IdentityScopeLocal): only the Cilium pod
	// on the same node as the client will have the resolved IPs in its IPCache.
	ciliumPod, err := s.ciliumPodOnNode(t, client.Pod.Spec.NodeName)
	if err != nil {
		t.Fatalf("Failed to find Cilium pod on node %s: %s", client.Pod.Spec.NodeName, err)
	}

	// Pick the IP family to use for the IP-based reachability checks.
	// Prefer IPv4 if available, fall back to IPv6 for IPv6-only clusters.
	ipFam := features.IPFamilyV4
	allowedIP := params.ExternalIPv4
	blockedIP := params.ExternalOtherIPv4
	if !ct.Features[features.IPv4].Enabled {
		ipFam = features.IPFamilyV6
		allowedIP = params.ExternalIPv6
		blockedIP = params.ExternalOtherIPv6
	}

	allowedHost := params.ExternalTarget
	blockedHost := params.ExternalOtherTarget
	allowedIPURL := fmt.Sprintf("http://%s", net.JoinHostPort(allowedIP, "80"))
	blockedIPURL := fmt.Sprintf("http://%s", net.JoinHostPort(blockedIP, "80"))

	t.Logf("Verifying pre-restart connectivity")
	s.assertReachable(ctx, t, client, "http://"+allowedHost, true)
	s.assertReachable(ctx, t, client, "http://"+blockedHost, false)
	s.assertReachable(ctx, t, client, allowedIPURL, true)
	s.assertReachable(ctx, t, client, blockedIPURL, false)

	// Record the numeric identity for the allowed IP before restart so we can
	// verify it is stable across the restart.
	identityBefore, err := s.ipCacheIdentity(ctx, ciliumPod, allowedIP, ipFam)
	if err != nil {
		t.Fatalf("Failed to get identity for %s before restart: %s", allowedIP, err)
	}
	t.Logf("Identity for %s before restart: %d", allowedIP, identityBefore)

	// Record the old pod name so we can wait for it to be fully gone before
	// checking connectivity during the restart.
	oldPodName := ciliumPod.Pod.Name

	t.Logf("Restarting Cilium pods")
	if err := ct.RolloutRestartCiliumPods(ctx); err != nil {
		t.Fatalf("Failed to restart Cilium pods: %s", err)
	}

	// Wait for the pod on the client's node to be fully terminated. This
	// ensures connectivity is enforced by the eBPF datapath alone, with no
	// Cilium agent running.
	if err := check.WaitForCiliumPodGone(ctx, t, ciliumPod.K8sClient, params.CiliumNamespace, oldPodName); err != nil {
		t.Fatalf("Cilium pod %s did not terminate: %s", oldPodName, err)
	}

	t.Logf("Verifying IP-based connectivity while Cilium is restarting")
	s.assertReachable(ctx, t, client, allowedIPURL, true)
	s.assertReachable(ctx, t, client, blockedIPURL, false)

	if err := check.WaitForDaemonSet(ctx, t, ciliumPod.K8sClient, params.CiliumNamespace, params.AgentDaemonSetName); err != nil {
		t.Fatalf("Cilium DaemonSet not ready after restart: %s", err)
	}
	t.Logf("Cilium is ready after restart")

	// Refresh the cached Cilium pod list now we've restarted cilium
	if err = ct.RefreshCiliumPods(ctx); err != nil {
		t.Fatalf("Failed to refresh Cilium pods after restart: %s", err)
	}
	ciliumPod, err = s.ciliumPodOnNode(t, client.Pod.Spec.NodeName)
	if err != nil {
		t.Fatalf("Failed to find Cilium pod on node %s after restart: %s", client.Pod.Spec.NodeName, err)
	}

	// Identities should have remained stable during a restart
	identityAfter, err := s.ipCacheIdentity(ctx, ciliumPod, allowedIP, ipFam)
	if err != nil {
		t.Fatalf("Failed to get identity for %s after restart: %s", allowedIP, err)
	}
	t.Logf("Identity for %s after restart: %d", allowedIP, identityAfter)
	if identityBefore != identityAfter {
		t.Failf("Identity for %s changed across restart: %d → %d (CIDR identity instability)",
			allowedIP, identityBefore, identityAfter)
	}

	t.Logf("Verifying post-restart connectivity")
	s.assertReachable(ctx, t, client, "http://"+allowedHost, true)
	s.assertReachable(ctx, t, client, "http://"+blockedHost, false)
	s.assertReachable(ctx, t, client, allowedIPURL, true)
	s.assertReachable(ctx, t, client, blockedIPURL, false)
}

func (s *fqdnRestoreAfterRestart) ciliumPodOnNode(t *check.Test, nodeName string) (*check.Pod, error) {
	for _, p := range t.Context().CiliumPods() {
		pod := p
		if pod.Pod.Spec.NodeName == nodeName {
			return &pod, nil
		}
	}
	return nil, fmt.Errorf("no Cilium pod found on node %s", nodeName)
}

func (s *fqdnRestoreAfterRestart) assertReachable(ctx context.Context, t *check.Test, pod *check.Pod, url string, expectSuccess bool) {
	maxTime := "10"
	if !expectSuccess {
		maxTime = "5"
	}
	peer := check.HTTPEndpoint("target", url)
	cmd := t.Context().CurlCommandWithOutput(peer, features.IPFamilyAny, expectSuccess, []string{"--max-time", maxTime})
	_, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name,
		pod.Pod.Spec.Containers[0].Name, cmd)

	if expectSuccess && err != nil {
		t.Failf("Expected curl to %s to succeed, got: %s", url, err)
	} else if !expectSuccess && err == nil {
		t.Failf("Expected curl to %s to fail, but it succeeded", url)
	}
}

func (s *fqdnRestoreAfterRestart) ipCacheIdentity(ctx context.Context, ciliumPod *check.Pod, ip string, ipFam features.IPFamily) (int64, error) {
	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx,
		ciliumPod.Pod.Namespace, ciliumPod.Pod.Name,
		defaults.AgentContainerName,
		[]string{"cilium-dbg", "ip", "list", "-o", "json"})
	if err != nil {
		return 0, err
	}

	var entries []struct {
		CIDR     string `json:"cidr"`
		Identity int64  `json:"identity"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		return 0, err
	}

	mask := "/32"
	if ipFam == features.IPFamilyV6 {
		mask = "/128"
	}
	cidr := ip + mask
	for _, e := range entries {
		if e.CIDR == cidr {
			return e.Identity, nil
		}
	}
	return 0, fmt.Errorf("Identity for %s not found in IPCache", ip)
}
