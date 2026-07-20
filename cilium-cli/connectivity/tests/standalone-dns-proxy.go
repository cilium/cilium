// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// standaloneDNSProxyPodSelector is the label selector of the Standalone DNS
// Proxy DaemonSet pods.
const standaloneDNSProxyPodSelector = "k8s-app=standalone-dns-proxy"

// StandaloneDNSProxy validates that the Standalone DNS Proxy (SDP) keeps
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

	// Deterministically pick a single client pod; the Cilium agent on its node
	// is the one taken down to validate SDP resilience.
	client := firstClientPod(ct)
	if client == nil {
		t.Fatal("No client pods available for the standalone-dns-proxy test")
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
func (s *standaloneDNSProxy) curl(ctx context.Context, t *check.Test, client *check.Pod, peer check.TestPeer, ipFam features.IPFamily, name string) {
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
func (s *standaloneDNSProxy) disableAgentOnNode(ctx context.Context, t *check.Test, node string) {
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

// firstClientPod returns the client pod with the lowest name, or nil if there
// are none. Selecting deterministically keeps the test reproducible.
func firstClientPod(ct *check.ConnectivityTest) *check.Pod {
	pods := ct.ClientPods()
	names := make([]string, 0, len(pods))
	for name := range pods {
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	pod := pods[names[0]]
	return &pod
}
