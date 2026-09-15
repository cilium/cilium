// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// standaloneDNSProxyPodSelector is the label selector of the Standalone DNS
// Proxy DaemonSet pods.
const standaloneDNSProxyPodSelector = "k8s-app=standalone-dns-proxy"

// dnsProxyMetric is the Cilium agent counter that both DNS proxies (the in-agent
// proxy and the Standalone DNS Proxy) feed via the agent. The proxy_type label
// is always "fqdn" for DNS.
const dnsProxyMetric = "cilium_policy_l7_total"

const (
	// sdpAllowedRequests and sdpDeniedRequests are the number of DNS requests
	// sent for the allowed and denied domains respectively during the
	// functional test. They are large enough that, given DNS load is shared
	// between the in-agent proxy and the Standalone DNS Proxy, at least some
	// requests are served by the SDP.
	sdpAllowedRequests = 10
	sdpDeniedRequests  = 10

	// sdpMetricSettle is a short grace period to let the DNS proxy metrics
	// settle before the "after" snapshot is taken. SDP-served requests are
	// reported to the agent over gRPC, so their metric increments may lag
	// slightly behind the curl returning.
	sdpMetricSettle = 3 * time.Second

	// sdpFlowWait bounds how long a single probe waits for its DNS flow(s) to be
	// captured by the Hubble flow listener before counting SDP attribution.
	sdpFlowWait = 5 * time.Second
)

// StandaloneDNSProxy validates that the Standalone DNS Proxy (SDP) is actively
// serving DNS while the Cilium agent is up.
//
// It sends a batch of allowed and a batch of denied DNS requests from a single
// client pod and asserts, in two independent validation states:
//
//  1. Functional counts (metrics): the agent's DNS proxy counter
//     (cilium_policy_l7_total{proxy_type="fqdn"}) records at least one
//     "forwarded" verdict per allowed request and at least one "denied" verdict
//     per denied request. The counter is fed by both DNS proxies, so the delta
//     reflects the total DNS load.
//  2. SDP attribution (flows): a subset of the DNS flows carry
//     observation_source="standalone-proxy", proving the SDP handled part of the
//     load for both allowed and denied requests.
//
// Metric assertions are skipped when the agent does not expose Prometheus
// metrics; SDP flow-attribution assertions are skipped when Hubble is disabled.
// The per-request curl outcome (success for the allowed domain, failure for the
// denied domain whose DNS is refused) is validated via the exit code provided
// by the test's registered expectations.
//
// NOTE: DNS load sharing between the two proxies is non-deterministic and a
// single curl may emit more than one DNS query, so counts are asserted as lower
// bounds ("at least N", "at least one served by the SDP") with the actual values
// logged. Pinning exact counts would require cluster-specific calibration.
// Observed on a 2-node kind cluster (10 allowed + 10 denied curls): forwarded
// delta ~20 (A+AAAA per curl), denied delta ~30 (REFUSED triggers resolver
// retries), and the SDP-attributed flow share varied run-to-run (e.g. 14/15 then
// 10/12), confirming the load-share is not fixed.
func StandaloneDNSProxy() check.Scenario {
	return &standaloneDNSProxy{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type standaloneDNSProxy struct {
	check.ScenarioBase
}

func (s *standaloneDNSProxy) Name() string {
	return "standalone-dns-proxy"
}

func (s *standaloneDNSProxy) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	ipFam := features.IPFamilyV4

	client := ct.RandomClientPod()
	if client == nil {
		t.Fatal("No client pods available for the standalone-dns-proxy test")
	}
	node := client.NodeName()

	allowed := check.HTTPEndpoint("sdp-allowed-"+ct.Params().ExternalTarget, "http://"+ct.Params().ExternalTarget)
	blocked := check.HTTPEndpoint("sdp-blocked-"+ct.Params().ExternalOtherTarget, "http://"+ct.Params().ExternalOtherTarget)

	forwardedLabels := map[string]string{"proxy_type": "fqdn", "rule": "forwarded"}
	deniedLabels := map[string]string{"proxy_type": "fqdn", "rule": "denied"}

	beforeForwarded := s.metric(t, node, forwardedLabels)
	beforeDenied := s.metric(t, node, deniedLabels)

	// Allowed batch: DNS resolves through the proxy (forwarded) and the
	// connection to port 80 succeeds.
	t.Logf("[sdp] Sending %d allowed DNS requests for %q", sdpAllowedRequests, ct.Params().ExternalTarget)
	sdpAllowed := 0
	for i := 0; i < sdpAllowedRequests; i++ {
		sdpAllowed += s.probe(ctx, t, client, allowed, ipFam, fmt.Sprintf("allowed-%d", i))
	}

	// Denied batch: DNS is refused by the proxy (denied), so curl fails to
	// resolve the name.
	t.Logf("[sdp] Sending %d denied DNS requests for %q", sdpDeniedRequests, ct.Params().ExternalOtherTarget)
	sdpDenied := 0
	for i := 0; i < sdpDeniedRequests; i++ {
		sdpDenied += s.probe(ctx, t, client, blocked, ipFam, fmt.Sprintf("denied-%d", i))
	}

	// Let the DNS proxy metrics settle; SDP reports its verdicts to the agent
	// over gRPC.
	time.Sleep(sdpMetricSettle)

	afterForwarded := s.metric(t, node, forwardedLabels)
	afterDenied := s.metric(t, node, deniedLabels)

	// Validation state 1: functional counts via agent metrics.
	if ct.CiliumAgentMetrics().IsEmpty() {
		t.Logf("[sdp] Cilium agent Prometheus metrics unavailable; skipping DNS proxy metric assertions")
	} else {
		forwardedDelta := afterForwarded - beforeForwarded
		deniedDelta := afterDenied - beforeDenied
		t.Logf("[sdp] DNS proxy metric deltas on node %q: forwarded=%.0f (>= %d expected), denied=%.0f (>= %d expected)",
			node, forwardedDelta, sdpAllowedRequests, deniedDelta, sdpDeniedRequests)
		if forwardedDelta < float64(sdpAllowedRequests) {
			t.Failf("expected at least %d forwarded DNS proxy events on node %q, got %.0f", sdpAllowedRequests, node, forwardedDelta)
		}
		if deniedDelta < float64(sdpDeniedRequests) {
			t.Failf("expected at least %d denied DNS proxy events on node %q, got %.0f", sdpDeniedRequests, node, deniedDelta)
		}
	}

	// Validation state 2: SDP attribution via Hubble flows.
	if !ct.Params().Hubble {
		t.Logf("[sdp] Hubble disabled; skipping standalone DNS proxy flow-attribution assertions")
		return
	}
	t.Logf("[sdp] DNS flows attributed to the standalone DNS proxy: allowed=%d, denied=%d", sdpAllowed, sdpDenied)
	if sdpAllowed < 1 {
		t.Failf("expected at least one allowed DNS flow served by the standalone DNS proxy, got %d", sdpAllowed)
	}
	if sdpDenied < 1 {
		t.Failf("expected at least one denied DNS flow served by the standalone DNS proxy, got %d", sdpDenied)
	}
}

// metric returns the sum of the DNS proxy counter on the given node for the
// provided label set, failing the test on error. It returns 0 when the agent
// does not expose Prometheus metrics (the caller treats that as "skip").
func (s *standaloneDNSProxy) metric(t *check.Test, node string, labels map[string]string) float64 {
	v, err := t.Context().SumCiliumAgentMetric(node, dnsProxyMetric, labels)
	if err != nil {
		t.Fatalf("Failed to read %s%v on node %q: %s", dnsProxyMetric, labels, node, err)
	}
	return v
}

// probe issues a single curl from the client pod and returns the number of DNS
// flows generated by that request that were served by the Standalone DNS Proxy
// (observation_source="standalone-proxy"). Flow collection is a no-op when
// Hubble is disabled, in which case this returns 0. The curl exit code is
// validated by ExecInPod against the test's registered expectations.
func (s *standaloneDNSProxy) probe(ctx context.Context, t *check.Test, client *check.Pod, peer check.TestPeer, ipFam features.IPFamily, name string) int {
	a := t.NewAction(s, name, client, peer, ipFam)

	sdp := 0
	a.Run(func(a *check.Action) {
		a.ExecInPod(ctx, a.CurlCommand(peer))

		if !t.Context().Params().Hubble {
			return
		}
		// Wait (bounded) for this request's DNS flow(s) to be captured, since
		// flows may arrive slightly after curl returns, then count the ones
		// attributed to the standalone DNS proxy.
		anyDNS := filters.DNS("", math.MaxUint32)
		sdpDNS := filters.DNSObservationSource("", math.MaxUint32, "standalone-proxy")
		for deadline := time.Now().Add(sdpFlowWait); time.Now().Before(deadline); {
			if a.CountFlows(anyDNS) > 0 {
				break
			}
			time.Sleep(check.PollInterval)
		}
		sdp = a.CountFlows(sdpDNS)
	})
	return sdp
}

// StandaloneDNSProxyHA validates that the Standalone DNS Proxy (SDP) keeps
// enforcing toFQDNs/DNS policy for previously-resolved domains while the Cilium
// agent on the client's node is unavailable.
//
// The scenario runs in two phases:
//
//  1. With the Cilium agent running, it establishes a baseline and, crucially,
//     primes the DNS cache and toFQDNs identity for the allowed domain. The SDP
//     cannot allocate new identities while the agent is down, so the allowed
//     domain must have been observed beforehand.
//  2. It takes the Cilium agent down on the client's node only (leaving the SDP
//     DaemonSet pod running) and verifies that the allowed domain still resolves
//     via the SDP and connects, while the blocked domain stays dropped.
//
// Hubble runs inside the agent and is therefore unavailable during phase 2, so
// every action validates via curl exit codes only (flow collection disabled).
func StandaloneDNSProxyHA() check.Scenario {
	return &standaloneDNSProxyHA{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type standaloneDNSProxyHA struct {
	check.ScenarioBase
}

func (s *standaloneDNSProxyHA) Name() string {
	return "standalone-dns-proxy-ha"
}

func (s *standaloneDNSProxyHA) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	ipFam := features.IPFamilyV4

	// Pick a single client pod; the Cilium agent on its node is the one taken
	// down to validate SDP resilience.
	client := ct.RandomClientPod()
	if client == nil {
		t.Fatal("No client pods available for the standalone-dns-proxy-ha test")
	}
	node := client.NodeName()

	allowed := check.HTTPEndpoint("sdp-allowed-"+ct.Params().ExternalTarget, "http://"+ct.Params().ExternalTarget)
	blocked := check.HTTPEndpoint("sdp-blocked-"+ct.Params().ExternalOtherTarget, "http://"+ct.Params().ExternalOtherTarget)

	// Phase 1 (agent up): baseline and DNS-cache priming.
	t.Logf("[sdp] Phase 1: Cilium agent up, priming DNS cache and validating baseline policy")
	s.curl(ctx, t, client, allowed, ipFam, "agent-up-allowed")
	s.curl(ctx, t, client, blocked, ipFam, "agent-up-blocked")

	// Take the Cilium agent down on the client's node only. Restore is registered
	// as a finalizer, so the agent is always brought back even if a later probe
	// calls Fatal().
	t.Logf("[sdp] Disabling the Cilium agent on node %q (standalone DNS proxy stays up)", node)
	s.disableAgentOnNode(ctx, t, node)

	// Phase 2 (agent down): the SDP must keep serving DNS and enforcing policy.
	t.Logf("[sdp] Phase 2: Cilium agent down, validating standalone DNS proxy still enforces DNS policy")
	s.curl(ctx, t, client, allowed, ipFam, "agent-down-allowed")
	s.curl(ctx, t, client, blocked, ipFam, "agent-down-blocked")
}

// curl runs a single curl action from the client pod. Flow validation depends on
// Hubble, which runs inside the agent and is unavailable once the agent is down,
// so the expected outcome is asserted via the curl exit code only (provided by
// the test's registered expectations).
func (s *standaloneDNSProxyHA) curl(ctx context.Context, t *check.Test, client *check.Pod, peer check.TestPeer, ipFam features.IPFamily, name string) {
	a := t.NewAction(s, name, client, peer, ipFam)
	a.CollectFlows = false
	a.Run(func(a *check.Action) {
		a.ExecInPod(ctx, a.CurlCommand(peer))
	})
}

// disableAgentOnNode patches the Cilium agent DaemonSet with a node-affinity rule
// that excludes the given node, causing the agent pod there to terminate without
// being rescheduled. The Standalone DNS Proxy DaemonSet is left untouched and
// keeps running on the node. The original affinity is restored via a finalizer.
//
// A node-affinity patch is used because the Cilium agent tolerates all taints,
// so cordoning or tainting the node would not evict it.
func (s *standaloneDNSProxyHA) disableAgentOnNode(ctx context.Context, t *check.Test, node string) {
	ct := t.Context()
	ns := ct.Params().CiliumNamespace
	dsName := ct.Params().AgentDaemonSetName

	ds, err := ct.K8sClient().GetDaemonSet(ctx, ns, dsName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get Cilium agent DaemonSet %s/%s: %s", ns, dsName, err)
	}

	// Record the original affinity so it can be restored exactly.
	origAffinityNil := ds.Spec.Template.Spec.Affinity == nil
	var origNodeAffinity *corev1.NodeAffinity
	if !origAffinityNil {
		origNodeAffinity = ds.Spec.Template.Spec.Affinity.NodeAffinity
	}

	// Register the restore before mutating anything, so the agent is brought back
	// even if the steps below or the phase 2 probes fail via Fatal(). Finalizers
	// run in the test's deferred teardown with a detached context.
	t.WithFinalizer(func(context.Context) error {
		t.Logf("[sdp] Restoring the Cilium agent on node %q", node)
		fctx, cancel := context.WithTimeout(context.Background(), check.LongTimeout)
		defer cancel()
		if err := patchAgentNodeAffinity(fctx, ct, origAffinityNil, origNodeAffinity); err != nil {
			return fmt.Errorf("restoring Cilium agent DaemonSet affinity: %w", err)
		}
		if err := check.WaitForDaemonSet(fctx, ct, ct.K8sClient(), ns, dsName); err != nil {
			return fmt.Errorf("waiting for Cilium agent DaemonSet to recover: %w", err)
		}
		// The agent pod was recreated with a new name, so the framework's cached
		// Cilium pod set is now stale. Refresh it before the remaining finalizers
		// (policy-revision wait, agent log collection) run against it.
		if err := ct.RefreshCiliumPods(fctx); err != nil {
			return fmt.Errorf("refreshing Cilium pod cache after agent recovery: %w", err)
		}
		return nil
	})

	// Exclude the node from the Cilium agent DaemonSet.
	excluded := &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key:      "kubernetes.io/hostname",
					Operator: corev1.NodeSelectorOpNotIn,
					Values:   []string{node},
				}},
			}},
		},
	}
	if err := patchAgentNodeAffinity(ctx, ct, false, excluded); err != nil {
		t.Fatalf("Failed to patch Cilium agent DaemonSet affinity: %s", err)
	}

	if err := waitForAgentGoneOnNode(ctx, ct, node); err != nil {
		t.Fatalf("Cilium agent did not stop on node %q: %s", node, err)
	}
	if err := waitForSDPReadyOnNode(ctx, ct, node); err != nil {
		t.Fatalf("Standalone DNS proxy is not ready on node %q: %s", node, err)
	}
}

// patchAgentNodeAffinity applies a JSON merge patch to the Cilium agent
// DaemonSet that sets spec.template.spec.affinity.nodeAffinity to the provided
// value. When removeAffinity is true, the whole affinity object is removed
// instead (used to restore a DaemonSet that originally had no affinity at all).
func patchAgentNodeAffinity(ctx context.Context, ct *check.ConnectivityTest, removeAffinity bool, nodeAffinity *corev1.NodeAffinity) error {
	var affinity any
	if !removeAffinity {
		// A nil nodeAffinity marshals to null, removing only the nodeAffinity
		// field while preserving any pod (anti-)affinity that was already set.
		affinity = map[string]any{"nodeAffinity": nodeAffinity}
	}
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"affinity": affinity,
				},
			},
		},
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = ct.K8sClient().PatchDaemonSet(ctx, ct.Params().CiliumNamespace, ct.Params().AgentDaemonSetName,
		types.MergePatchType, data, metav1.PatchOptions{})
	return err
}

// waitForAgentGoneOnNode waits until no Cilium agent pod is running on the node.
func waitForAgentGoneOnNode(ctx context.Context, ct *check.ConnectivityTest, node string) error {
	ctx, cancel := context.WithTimeout(ctx, check.LongTimeout)
	defer cancel()
	for {
		pods, err := ct.K8sClient().ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{
			LabelSelector: ct.Params().AgentPodSelector,
			FieldSelector: "spec.nodeName=" + node,
		})
		if err == nil && len(pods.Items) == 0 {
			return nil
		}
		select {
		case <-time.After(check.PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for the Cilium agent pod to terminate on node %q", node)
		}
	}
}

// waitForSDPReadyOnNode waits until a Standalone DNS Proxy pod is ready on the node.
func waitForSDPReadyOnNode(ctx context.Context, ct *check.ConnectivityTest, node string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*check.ShortTimeout)
	defer cancel()
	for {
		pods, err := ct.K8sClient().ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{
			LabelSelector: standaloneDNSProxyPodSelector,
			FieldSelector: "spec.nodeName=" + node,
		})
		if err == nil {
			for i := range pods.Items {
				if isPodReady(&pods.Items[i]) {
					return nil
				}
			}
		}
		select {
		case <-time.After(check.PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for a standalone DNS proxy pod to become ready on node %q", node)
		}
	}
}

func isPodReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
