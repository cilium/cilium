// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
)

const (
	LongTimeout  = 5 * time.Minute
	ShortTimeout = 30 * time.Second

	PollInterval = 1 * time.Second

	// daemonSetRejectionGrace is how much longer WaitForDaemonSet keeps polling
	// past LongTimeout when the DaemonSet is only held back by pods that were
	// rejected before running. kubelet's rejection backoff reaches roughly four
	// minutes, so this has to cover one burst plus the scheduling that follows.
	daemonSetRejectionGrace = 5 * time.Minute

	// execProxyTimeout bounds how long pollExecProbe keeps retrying while the
	// only thing failing is the exec proxy itself, not the probe. The
	// kube-apiserver -> kubelet exec proxy on managed clusters (seen on AKS) can
	// be unreachable for tens of seconds at a time, longer than ShortTimeout, so
	// these failures get their own generous allowance instead of consuming the
	// readiness budget of whatever is being waited for.
	execProxyTimeout = 3 * time.Minute
)

// pollExecProbe polls probe until it succeeds or its deadline is reached.
//
// The readiness deadline governs how long we wait for whatever the probe
// measures to become ready. A transient exec-proxy failure is not a verdict on
// that, so it is bounded by the generous execProxyTimeout instead and must not
// count against readiness. Any other error means the probe actually ran and
// reported not-ready, so it is bounded by readiness as usual.
//
// Probes must exec against the parent context, never against a context derived
// from the readiness deadline: the exec dial has no timeout of its own, so a
// blackholed connection to the apiserver burns the entire readiness budget on a
// single attempt and leaves the loop with no retry at all.
func pollExecProbe(parentCtx context.Context, readiness time.Duration, probe func() error) error {
	readinessDeadline := time.Now().Add(readiness)
	execProxyDeadline := time.Now().Add(execProxyTimeout)
	for {
		err := probe()
		if err == nil {
			return nil
		}

		deadline := readinessDeadline
		if k8s.IsTransientExecError(err) {
			deadline = execProxyDeadline
		}
		if time.Now().After(deadline) {
			return err
		}

		select {
		case <-time.After(PollInterval):
		case <-parentCtx.Done():
			return err
		}
	}
}

// WaitForDeployment waits until the specified deployment becomes ready.
func WaitForDeployment(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) error {
	log.Logf("⌛ [%s] Waiting for deployment %s/%s to become ready...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, LongTimeout)
	defer cancel()
	for {
		err := client.CheckDeploymentStatus(ctx, namespace, name)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] Deployment %s/%s is not yet ready: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for deployment %s/%s to become ready (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForDaemonSet waits until the specified daemonset becomes ready.
//
// A node condition such as DiskPressure makes kubelet reject the pods bound to
// it, and each rejection is retried on an exponential backoff that reaches
// several minutes on its own. LongTimeout cannot outlast one such burst, so
// when the deadline is reached and the only thing holding the DaemonSet back is
// pods that were rejected without ever running, keep polling for a bounded
// grace period instead of failing. Anything else, including a container that
// ran and crashed, still fails at LongTimeout.
func WaitForDaemonSet(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) error {
	log.Logf("⌛ [%s] Waiting for DaemonSet %s/%s to become ready...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, LongTimeout+daemonSetRejectionGrace)
	defer cancel()

	deadline := time.Now().Add(LongTimeout)
	graceGranted := false
	for {
		err := client.CheckDaemonSetStatus(ctx, namespace, name)
		if err == nil {
			return nil
		}

		log.Debugf("[%s] DaemonSet %s/%s is not yet ready: %s", client.ClusterName(), namespace, name, err)

		if !graceGranted && time.Now().After(deadline) {
			rejected := supersededDaemonSetPods(ctx, client, namespace, name)
			if len(rejected) == 0 {
				return fmt.Errorf("timeout reached waiting for DaemonSet %s/%s to become ready (last error: %w)",
					namespace, name, err)
			}
			graceGranted = true
			log.Logf("⌛ [%s] DaemonSet %s/%s is held back by pods rejected before running (%s), waiting up to %s more...",
				client.ClusterName(), namespace, name, strings.Join(rejected, ", "), daemonSetRejectionGrace)
		}

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			if rejected := supersededDaemonSetPods(ctx, client, namespace, name); len(rejected) > 0 {
				return fmt.Errorf("timeout reached waiting for DaemonSet %s/%s to become ready, pods rejected before running: %s (last error: %w)",
					namespace, name, strings.Join(rejected, ", "), err)
			}
			return fmt.Errorf("timeout reached waiting for DaemonSet %s/%s to become ready (last error: %w)",
				namespace, name, err)
		}
	}
}

// supersededDaemonSetPods returns "pod (reason)" for every pod of the DaemonSet
// that reached a terminal state without ever running its workload, but only if
// no other pod failed for a different reason. A pod that ran and crashed leaves
// the result empty, so its DaemonSet is never granted the extra grace period.
func supersededDaemonSetPods(ctx context.Context, client *k8s.Client, namespace, name string) []string {
	ds, err := client.GetDaemonSet(ctx, namespace, name, metav1.GetOptions{})
	if err != nil || ds == nil {
		return nil
	}

	pods, err := client.ListPods(ctx, namespace, metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(ds.Spec.Selector),
	})
	if err != nil || pods == nil {
		return nil
	}

	var rejected []string
	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodFailed {
			continue
		}
		if !k8s.IsSupersededPodRejection(pod.Status.Reason) {
			return nil
		}
		rejected = append(rejected, fmt.Sprintf("%s (%s)", pod.Name, pod.Status.Reason))
	}
	return rejected
}

// WaitForPodDNS waits until src can query the DNS server on dst successfully.
func WaitForPodDNS(parentCtx context.Context, log Logger, src, dst Pod) error {
	log.Logf("⌛ [%s] Waiting for pod %s to reach DNS server on %s pod...",
		src.K8sClient.ClusterName(), src.Name(), dst.Name())

	// We don't care about the actual response content, we just want to check the DNS operativity.
	// Since the coreDNS test server has been deployed with the "local" plugin enabled,
	// we query it with a so-called "local request" (e.g. "localhost") to get a response.
	// See https://coredns.io/plugins/local/ for more info.
	target := "localhost"
	err := pollExecProbe(parentCtx, ShortTimeout, func() error {
		stdout, err := src.K8sClient.ExecInPod(parentCtx, src.Namespace(), src.NameWithoutNamespace(),
			src.Pod.Spec.Containers[0].Name, []string{"nslookup", target, dst.Address(features.IPFamilyAny)})
		if err != nil {
			log.Debugf("[%s] Error looking up %s from pod %s to server on pod %s: %s: %s",
				src.K8sClient.ClusterName(), target, src.Name(), dst.Name(), err, stdout.String())
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("timeout reached waiting for lookup for %s from pod %s to server on pod %s to succeed (last error: %w)",
			target, src.Name(), dst.Name(), err,
		)
	}

	return nil
}

// WaitForCoreDNS waits until the client pod can reach coredns.
func WaitForCoreDNS(parentCtx context.Context, log Logger, client Pod) error {
	log.Logf("⌛ [%s] Waiting for pod %s to reach default/kubernetes service...",
		client.K8sClient.ClusterName(), client.Name())

	target := "kubernetes.default"
	err := pollExecProbe(parentCtx, ShortTimeout, func() error {
		stdout, err := client.K8sClient.ExecInPod(parentCtx, client.Namespace(), client.NameWithoutNamespace(),
			client.Pod.Spec.Containers[0].Name, []string{"nslookup", target})
		if err != nil {
			log.Debugf("[%s] Error looking up %s from pod %s: %s: %s",
				client.K8sClient.ClusterName(), target, client.Name(), err, stdout.String())
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("timeout reached waiting for lookup for %s from pod %s to succeed (last error: %w)",
			target, client.Name(), err)
	}

	return nil
}

// Service waits until the specified service is created and can be retrieved.
func WaitForServiceRetrieval(ctx context.Context, log Logger, client *k8s.Client, namespace string, name string) (Service, error) {
	log.Logf("⌛ [%s] Retrieving service %s/%s ...", client.ClusterName(), namespace, name)

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()
	for {
		svc, err := client.GetService(ctx, namespace, name, metav1.GetOptions{})
		if err == nil {
			return Service{Service: svc.DeepCopy()}, nil
		}

		log.Debugf("[%s] Failed to retrieve Service %s/%s: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-time.After(PollInterval):
		case <-ctx.Done():
			return Service{}, fmt.Errorf("timeout reached waiting for service %s/%s to be retrieved (last error: %w)",
				namespace, name, err)
		}
	}
}

// WaitForService waits until the given service is synchronized in CoreDNS.
func WaitForService(parentCtx context.Context, log Logger, client Pod, service Service) error {
	log.Logf("⌛ [%s] Waiting for Service %s to become ready...", client.K8sClient.ClusterName(), service.Name())

	if service.Service.Spec.ClusterIP == corev1.ClusterIPNone {
		// If the cluster is headless there is nothing to wait for here
		return nil
	}

	err := pollExecProbe(parentCtx, 2*ShortTimeout, func() error {
		stdout, err := client.K8sClient.ExecInPod(parentCtx,
			client.Namespace(), client.NameWithoutNamespace(), client.Pod.Spec.Containers[0].Name,
			[]string{"nslookup", service.Service.Name}) // BusyBox nslookup doesn't support any arguments.

		// Lookup successful.
		if err == nil {
			svcIP := service.Service.Spec.ClusterIP
			if svcIP == "" {
				return nil
			}

			nslookupStr := strings.ReplaceAll(stdout.String(), "\r\n", "\n")
			if strings.Contains(nslookupStr, "Address: "+svcIP+"\n") {
				return nil
			}
			err = fmt.Errorf("Service IP %q not found in nslookup output %q", svcIP, nslookupStr)
		}

		log.Debugf("[%s] Error checking service %s: %s: %s",
			client.K8sClient.ClusterName(), service.Name(), err, stdout.String())

		return err
	})
	if err != nil {
		return fmt.Errorf("timeout reached waiting for service %s (last error: %w)", service.Name(), err)
	}

	return nil
}

// WaitForServiceEndpoints waits until the expected number of service backends
// are reported by the given agent.
func WaitForServiceEndpoints(parentCtx context.Context, log Logger, agent Pod, service Service, backends uint, families []features.IPFamily) error {
	log.Logf("⌛ [%s] Waiting for Service %s to be synchronized by Cilium pod %s",
		agent.K8sClient.ClusterName(), service.Name(), agent.Name())

	if service.Service.Spec.ClusterIP == corev1.ClusterIPNone {
		// If the cluster is headless there is nothing to wait for here
		return nil
	}

	// Use the same timeout as WaitForService above: with concurrent tests it
	// takes a little bit more time for all the services to be synchronized by
	// every agent, and 30 seconds occasionally isn't enough.
	err := pollExecProbe(parentCtx, 2*ShortTimeout, func() error {
		err := checkServiceEndpoints(parentCtx, agent, service, backends, families)
		if err != nil {
			log.Debugf("[%s] Service %s not yet correctly synchronized by Cilium pod %s: %s",
				agent.K8sClient.ClusterName(), service.Name(), agent.Name(), err)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("timeout reached waiting for service %s to appear in Cilium pod %s (last error: %w)",
			service.Name(), agent.Name(), err)
	}

	return nil
}

func checkServiceEndpoints(ctx context.Context, agent Pod, service Service, backends uint, families []features.IPFamily) error {
	buffer, err := agent.K8sClient.ExecInPod(ctx, agent.Namespace(), agent.NameWithoutNamespace(),
		defaults.AgentContainerName, []string{"cilium", "service", "list", "--output=json"})
	if err != nil {
		return fmt.Errorf("failed to query service list: %w", err)
	}

	var services []*models.Service
	if err := json.Unmarshal(buffer.Bytes(), &services); err != nil {
		return fmt.Errorf("failed to unmarshal service list output: %w", err)
	}

	type l3n4 struct {
		addr string
		port uint16
	}

	found := make(map[l3n4]uint)
	for _, svc := range services {
		found[l3n4{
			addr: svc.Spec.FrontendAddress.IP,
			port: svc.Spec.FrontendAddress.Port,
		}] = uint(len(svc.Spec.BackendAddresses))
	}

	for _, ip := range service.Service.Spec.ClusterIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("failed to parse ClusterIP %q: %w", ip, err)
		}

		// Skip the check for a given address if the corresponding IP family is not
		// enabled in Cilium, as the backends will never be populated.
		if addr.Is4() && !slices.Contains(families, features.IPFamilyV4) || addr.Is6() && !slices.Contains(families, features.IPFamilyV6) {
			continue
		}

		for _, port := range service.Service.Spec.Ports {
			if found[l3n4{addr: ip, port: uint16(port.Port)}] < backends {
				return errors.New("service not yet synchronized")
			}
		}
	}

	return nil
}

// WaitForNodePorts waits until all the nodeports in a service are available on a given node.
func WaitForNodePorts(parentCtx context.Context, log Logger, client Pod, nodeIP string, service Service) error {
	for _, port := range service.Service.Spec.Ports {
		nodePort := port.NodePort
		if nodePort == 0 {
			continue
		}

		log.Logf("⌛ [%s] Waiting for NodePort %s:%d (%s) to become ready...",
			client.K8sClient.ClusterName(), nodeIP, nodePort, service.Name())

		err := pollExecProbe(parentCtx, ShortTimeout, func() error {
			stdout, err := client.K8sClient.ExecInPod(parentCtx,
				client.Namespace(), client.NameWithoutNamespace(), client.Pod.Spec.Containers[0].Name,
				[]string{"nc", "-w", "3", "-z", nodeIP, strconv.Itoa(int(nodePort))})
			if err != nil {
				log.Debugf("[%s] Error checking NodePort %s:%d (%s): %s: %s",
					client.K8sClient.ClusterName(), nodeIP, nodePort, service.Name(), err, stdout.String())
			}
			return err
		})
		if err != nil {
			return fmt.Errorf("timeout reached waiting for NodePort %s:%d (%s) (last error: %w)",
				nodeIP, nodePort, service.Name(), err)
		}
	}

	return nil
}

// BPFEgressGatewayPolicyEntry represents an entry in the BPF egress gateway policy map
type BPFEgressGatewayPolicyEntry struct {
	SourceIP  string `json:"sourceIP"`
	DestCIDR  string `json:"destCIDR"`
	EgressIP  string `json:"egressIP"`
	GatewayIP string `json:"gatewayIP"`
}

// matches is an helper used to compare the receiver bpfEgressGatewayPolicyEntry with another entry
func (e *BPFEgressGatewayPolicyEntry) matches(t BPFEgressGatewayPolicyEntry) bool {
	return t.SourceIP == e.SourceIP &&
		t.DestCIDR == e.DestCIDR &&
		t.EgressIP == e.EgressIP &&
		t.GatewayIP == e.GatewayIP
}

// WaitForEgressGatewayBpfPolicyEntries waits for the egress gateway policy maps on each node to WaitForEgressGatewayBpfPolicyEntries
// with the entries returned by the targetEntriesCallback
func WaitForEgressGatewayBpfPolicyEntries(ctx context.Context,
	ciliumPods map[string]Pod,
	testPods []Pod,
	targetEntriesCallback func(ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error),
	excludeEntries func(ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error),
) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	localPodIPs := sets.New[string]()
	for _, pod := range testPods {
		if ip := pod.Address(features.IPFamilyV4); ip != "" {
			localPodIPs.Insert(ip)
		}
		if ip := pod.Address(features.IPFamilyV6); ip != "" {
			localPodIPs.Insert(ip)
		}
	}

	ensureBpfPolicyEntries := func() error {
		for _, ciliumPod := range ciliumPods {
			targetEntries, err := targetEntriesCallback(ciliumPod)
			if err != nil {
				return fmt.Errorf("failed to get target entries: %w", err)
			}

			cmd := strings.Split("cilium bpf egress list -o json", " ")
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				return fmt.Errorf("failed to run cilium bpf egress list command: %w", err)
			}

			var entries []BPFEgressGatewayPolicyEntry
			json.Unmarshal(stdout.Bytes(), &entries)

			excludes, err := excludeEntries(ciliumPod)
			if err != nil {
				return fmt.Errorf("failed to get exclude entries: %w", err)
			}
			for _, exclude := range excludes {
				entries = slices.DeleteFunc(entries, func(entry BPFEgressGatewayPolicyEntry) bool {
					return entry.matches(exclude)
				})
			}

			for _, targetEntry := range targetEntries {
				if !slices.ContainsFunc(entries, targetEntry.matches) {
					return fmt.Errorf("could not find egress gateway policy entry matching %+v", targetEntry)
				}
			}

			for _, entry := range entries {
				// We only check for untracked entries for Pods in this test namespace that
				// are untracked.
				if !localPodIPs.Has(entry.SourceIP) {
					continue
				}
				if !slices.ContainsFunc(targetEntries, entry.matches) {
					return fmt.Errorf("untracked entry %+v in the egress gateway policy maps", entry)
				}
			}
		}

		return nil
	}

	for {
		if err := ensureBpfPolicyEntries(); err != nil {
			if err := w.Retry(err); err != nil {
				return fmt.Errorf("failed to ensure egress gateway policy maps are properly populated: %w", err)
			}

			continue
		}

		return nil
	}
}

// DeleteK8sResourceWithWait deletes the provided k8s resource and waits until it is deleted.
func DeleteK8sResourceWithWait[T any](ctx context.Context, t *Test, k8sClient k8s.ResourceClient[T], resourceName string) {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: ShortTimeout})
	defer w.Cancel()

	err := k8sClient.Delete(ctx, resourceName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		t.Fatalf("Failed to delete k8s resorce %s: %v", resourceName, err)
	}
	for {
		_, err = k8sClient.Get(ctx, resourceName, metav1.GetOptions{})
		if err != nil && k8serrors.IsNotFound(err) {
			return // got expected not found
		}
		if err = w.Retry(err); err != nil {
			t.Fatalf("Failed to ensure k8s resorce %s is deleted: %v", resourceName, err)
		}
	}
}

// DeleteK8sObjectWithWait deletes the provided unstructured k8s object and waits until it is deleted.
func DeleteK8sObjectWithWait(ctx context.Context, t *Test, obj *unstructured.Unstructured) {
	err := t.Context().K8sClient().DeleteGeneric(ctx, obj)
	if err != nil && !k8serrors.IsNotFound(err) {
		t.Fatalf("Failed to delete k8s object %s: %v", obj.GetName(), err)
	}
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: ShortTimeout})
	defer w.Cancel()
	for {
		_, err := t.Context().K8sClient().GetGeneric(ctx, obj.GetNamespace(), obj.GetName(), obj)
		if err != nil && k8serrors.IsNotFound(err) {
			break // got expected not found
		}
		if err = w.Retry(err); err != nil {
			t.Fatalf("Failed to ensure k8s object %s is deleted: %v", obj.GetName(), err)
		}
	}
}
