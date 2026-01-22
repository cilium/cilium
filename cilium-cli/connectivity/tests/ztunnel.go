// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// Test scenario configuration constants
const (
	enrolledNamespace0  = "cilium-test-ztunnel-enrolled-0"
	enrolledNamespace1  = "cilium-test-ztunnel-enrolled-1"
	unenrolledNamespace = "cilium-test-ztunnel-unenrolled"
	ztunnelInboundPort  = 15008
	echoServerPort      = 8080
	ztunnelAdminPort    = "15000"
	spireNamespace      = "kube-system"
	spireServerPodName  = "spire-server-0"
	spireTrustDomain    = "cluster.local"
	maxCurlRetries      = 5
	curlRetryDelay      = 2 * time.Second

	// Namespace enrollment label for Cilium's ztunnel mTLS
	mtlsEnabledLabel = "mtls-enabled"
)

// podLocation defines whether pods are on the same or different nodes
type podLocation int

const (
	SameNode podLocation = iota
	DifferentNode
)

// enrollmentStatus defines whether a pod is enrolled in ztunnel mTLS
type enrollmentStatus int

const (
	Enrolled enrollmentStatus = iota
	Unenrolled
)

// scenarioConfig defines the configuration for a ztunnel test scenario
type scenarioConfig struct {
	name             string
	clientEnrollment enrollmentStatus
	serverEnrollment enrollmentStatus
	location         podLocation
	sameNamespace    bool
	expectEncryption bool
}

// ztunnelTestBase provides shared functionality for all ztunnel test scenarios
type ztunnelTestBase struct {
	check.ScenarioBase

	config scenarioConfig
	ct     *check.ConnectivityTest

	namespace string

	// pods under test
	client *check.Pod
	server *check.Pod

	// host network namespace pods
	clientHostNS *check.Pod
	serverHostNS *check.Pod

	// ztunnel pods
	clientZTunnel *check.Pod
	serverZTunnel *check.Pod

	// feature flags
	encryptMode features.Status
	ipv4Enabled features.Status
	ipv6Enabled features.Status

	// finalizers to clean up resources
	finalizers []func() error
}

// ================================================================================
// Factory Functions for All Test Scenarios
// ================================================================================

// ZTunnelEnrolledToEnrolledSameNode tests mTLS encryption between enrolled pods on same node
func ZTunnelEnrolledToEnrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-same-node",
		clientEnrollment: Enrolled,
		serverEnrollment: Enrolled,
		location:         SameNode,
		sameNamespace:    true,
		expectEncryption: true,
	})
}

// ZTunnelEnrolledToEnrolledDifferentNode tests mTLS encryption between enrolled pods on different nodes
func ZTunnelEnrolledToEnrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-different-node",
		clientEnrollment: Enrolled,
		serverEnrollment: Enrolled,
		location:         DifferentNode,
		sameNamespace:    true,
		expectEncryption: true,
	})
}

// ZTunnelUnenrolledToUnenrolledSameNode tests plain traffic between unenrolled pods on same node
func ZTunnelUnenrolledToUnenrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-unenrolled-same-node",
		clientEnrollment: Unenrolled,
		serverEnrollment: Unenrolled,
		location:         SameNode,
		sameNamespace:    true,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToUnenrolledDifferentNode tests plain traffic between unenrolled pods on different nodes
func ZTunnelUnenrolledToUnenrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-unenrolled-different-node",
		clientEnrollment: Unenrolled,
		serverEnrollment: Unenrolled,
		location:         DifferentNode,
		sameNamespace:    true,
		expectEncryption: false,
	})
}

// ZTunnelEnrolledToUnenrolledSameNode tests traffic from enrolled to unenrolled pod on same node
func ZTunnelEnrolledToUnenrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-unenrolled-same-node",
		clientEnrollment: Enrolled,
		serverEnrollment: Unenrolled,
		location:         SameNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelEnrolledToUnenrolledDifferentNode tests traffic from enrolled to unenrolled pod on different nodes
func ZTunnelEnrolledToUnenrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-unenrolled-different-node",
		clientEnrollment: Enrolled,
		serverEnrollment: Unenrolled,
		location:         DifferentNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToEnrolledSameNode tests traffic from unenrolled to enrolled pod on same node
func ZTunnelUnenrolledToEnrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-enrolled-same-node",
		clientEnrollment: Unenrolled,
		serverEnrollment: Enrolled,
		location:         SameNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToEnrolledDifferentNode tests traffic from unenrolled to enrolled pod on different nodes
func ZTunnelUnenrolledToEnrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-enrolled-different-node",
		clientEnrollment: Unenrolled,
		serverEnrollment: Enrolled,
		location:         DifferentNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelEnrolledToEnrolledCrossNamespaceSameNode tests mTLS between enrolled pods in different namespaces on same node
func ZTunnelEnrolledToEnrolledCrossNamespaceSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-cross-ns-same-node",
		clientEnrollment: Enrolled,
		serverEnrollment: Enrolled,
		location:         SameNode,
		sameNamespace:    false,
		expectEncryption: true,
	})
}

// ZTunnelEnrolledToEnrolledCrossNamespaceDifferentNode tests mTLS between enrolled pods in different namespaces on different nodes
func ZTunnelEnrolledToEnrolledCrossNamespaceDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-cross-ns-different-node",
		clientEnrollment: Enrolled,
		serverEnrollment: Enrolled,
		location:         DifferentNode,
		sameNamespace:    false,
		expectEncryption: true,
	})
}

// ZTunnelUnenrolledToEnrolledCrossNamespaceSameNode tests traffic from unenrolled to enrolled pod in different namespaces on same node
func ZTunnelUnenrolledToEnrolledCrossNamespaceSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-enrolled-cross-ns-same-node",
		clientEnrollment: Unenrolled,
		serverEnrollment: Enrolled,
		location:         SameNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToEnrolledCrossNamespaceDifferentNode tests traffic from unenrolled to enrolled pod in different namespaces on different nodes
func ZTunnelUnenrolledToEnrolledCrossNamespaceDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-enrolled-cross-ns-different-node",
		clientEnrollment: Unenrolled,
		serverEnrollment: Enrolled,
		location:         DifferentNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// newZTunnelTest creates a new ztunnel test with the given configuration
func newZTunnelTest(config scenarioConfig) check.Scenario {
	return &ztunnelTestBase{
		ScenarioBase: check.NewScenarioBase(),
		config:       config,
	}
}

func (s *ztunnelTestBase) Name() string {
	return s.config.name
}

// ================================================================================
// Pod Selection Logic
// ================================================================================

// getNamespaceForEnrollment determines which namespace to use based on enrollment and pod type.
//
// Namespace distribution strategy:
// - All 3 test namespaces (enrolled-0, enrolled-1, unenrolled) start without the mtls-enabled label
// - During test execution, namespaces are dynamically labeled based on enrollment requirements
// - Unenrolled pods use "cilium-test-ztunnel-unenrolled"
// - Enrolled pods in same-namespace tests use "cilium-test-ztunnel-enrolled-0"
// - Enrolled pods in cross-namespace tests:
//   - Client pods → "cilium-test-ztunnel-enrolled-0"
//   - Server pods → "cilium-test-ztunnel-enrolled-1"
//
// This ensures we test both intra-namespace and inter-namespace mTLS scenarios,
// and verifies the full enrollment lifecycle (label → SPIRE entry creation → removal).
func (s *ztunnelTestBase) getNamespaceForEnrollment(enrollment enrollmentStatus, podType string) string {
	if enrollment == Unenrolled {
		return unenrolledNamespace
	}

	// For same namespace tests, always use enrolled-0
	if s.config.sameNamespace {
		return enrolledNamespace0
	}

	// For cross-namespace tests, client goes to enrolled-0, server to enrolled-1
	if podType == "client" {
		return enrolledNamespace0
	}
	return enrolledNamespace1
}

// getPod retrieves a pod matching the specified enrollment status, node location, and type.
//
// Pod type can be:
// - "client": The client pod that initiates HTTP requests
// - "echo-same-node": Echo server pod with node affinity to be on the same node as client
// - "echo-other-node": Echo server pod with anti-affinity to be on a different node
//
// Deployments are labeled with "name=<deployment-name>", so we list all pods with that label
// and then filter by node location requirements:
// - SameNode: Pod must be on the same node as referenceNode
// - DifferentNode: Pod must be on a different node than referenceNode
func (s *ztunnelTestBase) getPod(ctx context.Context, t *check.Test, enrollment enrollmentStatus, podType string, referenceNode string, location podLocation) *check.Pod {
	namespace := s.getNamespaceForEnrollment(enrollment, podType)

	// Determine label selector based on pod type
	// The deployment creates pods with label "name=<deployment-name>"
	var labelSelector string
	if podType == "client" {
		labelSelector = "name=client"
	} else {
		// For echo pods, use the full deployment name
		labelSelector = fmt.Sprintf("name=%s", podType)
	}

	pods, err := s.ct.K8sClient().ListPods(ctx, namespace, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		t.Fatalf("Failed to list %s pods in namespace %s with selector %s: %v", podType, namespace, labelSelector, err)
	}

	if len(pods.Items) == 0 {
		t.Fatalf("No %s pods found in namespace %s with selector %s", podType, namespace, labelSelector)
	}

	// Debug: log all found pods
	t.Debugf("Found %d pods for selector %s in namespace %s:", len(pods.Items), labelSelector, namespace)
	for i := range pods.Items {
		pod := &pods.Items[i]
		t.Debugf("  - %s on node %s (phase: %s)", pod.Name, pod.Spec.NodeName, pod.Status.Phase)
	}

	// Find a pod matching the location requirements
	pod := s.filterPodsByLocation(&pods.Items, referenceNode, location)
	if pod == nil {
		t.Fatalf("Failed to find %s pod matching node location requirements in namespace %s (selector: %s, referenceNode: %s, location: %s, found %d pods)",
			podType, namespace, labelSelector, referenceNode, locationName(location), len(pods.Items))
	}

	return &check.Pod{
		K8sClient: s.ct.K8sClient(),
		Pod:       pod,
	}
}

// filterPodsByLocation finds the first pod matching the specified node location constraint.
// Returns nil if no matching pod is found.
func (s *ztunnelTestBase) filterPodsByLocation(pods *[]corev1.Pod, referenceNode string, location podLocation) *corev1.Pod {
	for i := range *pods {
		pod := &(*pods)[i]
		if location == SameNode && referenceNode != "" {
			if pod.Spec.NodeName == referenceNode {
				return pod
			}
		} else if location == DifferentNode && referenceNode != "" {
			if pod.Spec.NodeName != referenceNode {
				return pod
			}
		} else {
			// No location constraint, return first pod
			return pod
		}
	}
	return nil
}

// setupTestPods configures client and server pods based on test configuration
func (s *ztunnelTestBase) setupTestPods(ctx context.Context, t *check.Test) {
	// Get client pod
	s.client = s.getPod(ctx, t, s.config.clientEnrollment, "client", "", SameNode)

	// Get server pod based on location and enrollment
	serverPodType := "echo-same-node"
	if s.config.location == DifferentNode {
		serverPodType = "echo-other-node"
	}

	s.server = s.getPod(ctx, t, s.config.serverEnrollment, serverPodType, s.client.Pod.Spec.NodeName, s.config.location)

	t.Debugf("Selected pods: client=%s (node=%s, ns=%s), server=%s (node=%s, ns=%s)",
		s.client.Pod.Name, s.client.Pod.Spec.NodeName, s.client.Pod.Namespace,
		s.server.Pod.Name, s.server.Pod.Spec.NodeName, s.server.Pod.Namespace)
}

// ================================================================================
// Host Network and Ztunnel Pod Helpers
// ================================================================================

// getHostNSPods acquires host namespace pods for packet capture on client and server nodes.
//
// Ztunnel runs as a DaemonSet in the host network namespace, so encrypted traffic between
// nodes flows through the host network stack, not the pod network. To capture this traffic
// with tcpdump, we need pods with:
// 1. Host network access (hostNetwork: true)
// 2. NET_ADMIN capability to run tcpdump
//
// These host network pods are deployed by the connectivity test framework.
func (s *ztunnelTestBase) getHostNSPods(t *check.Test) {
	clientHostNS, ok := s.ct.HostNetNSPodsByNode()[s.client.Pod.Spec.NodeName]
	if !ok {
		t.Fatalf("Failed to acquire host namespace pod on %s (client's node)", s.client.Pod.Spec.NodeName)
	}
	s.clientHostNS = &clientHostNS

	serverHostNS, ok := s.ct.HostNetNSPodsByNode()[s.server.Pod.Spec.NodeName]
	if !ok {
		t.Fatalf("Failed to acquire host namespace pod on %s (server's node)", s.server.Pod.Spec.NodeName)
	}
	s.serverHostNS = &serverHostNS
}

// getZTunnelPods acquires ztunnel pods running on the same nodes as client and server
func (s *ztunnelTestBase) getZTunnelPods(ctx context.Context, t *check.Test) {
	ztunnelPods, err := s.ct.K8sClient().ListPods(ctx, s.namespace, metav1.ListOptions{
		LabelSelector: "app=ztunnel-cilium",
	})
	if err != nil {
		t.Fatalf("Failed to list ztunnel pods: %s", err)
	}
	if len(ztunnelPods.Items) == 0 {
		t.Fatalf("No ztunnel pods found in namespace %s", s.namespace)
	}

	for i := range ztunnelPods.Items {
		pod := &ztunnelPods.Items[i]
		if pod.Status.HostIP == s.client.Pod.Status.HostIP {
			s.clientZTunnel = &check.Pod{Pod: pod}
		}
		if pod.Status.HostIP == s.server.Pod.Status.HostIP {
			s.serverZTunnel = &check.Pod{Pod: pod}
		}
	}

	if s.clientZTunnel == nil {
		t.Fatalf("Failed to acquire ztunnel pod on client node")
	}
	if s.serverZTunnel == nil {
		t.Fatalf("Failed to acquire ztunnel pod on server node")
	}
}

// ================================================================================
// Ztunnel State Validation
// ================================================================================

// workload represents a workload in the ztunnel dump_config output
type workload struct {
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"serviceAccount"`
	UID            string   `json:"uid"`
	WorkloadIPs    []string `json:"workloadIps"`
	Node           string   `json:"node"`
	Status         string   `json:"status"`
}

// ztunnelDumpConfig represents the dump_config response structure
type ztunnelDumpConfig struct {
	Workloads []workload `json:"workloads"`
}

// validateZTunnelState checks that ztunnels have workload information for enrolled pods
func (s *ztunnelTestBase) validateZTunnelState(ctx context.Context, t *check.Test) {
	// Skip validation if neither pod is enrolled
	if s.config.clientEnrollment == Unenrolled && s.config.serverEnrollment == Unenrolled {
		t.Debugf("Skipping ztunnel state validation - no enrolled pods")
		return
	}

	fetchWorkloads := func(hostNS *check.Pod) ([]workload, error) {
		stdout, err := hostNS.K8sClient.ExecInPod(
			ctx,
			hostNS.Pod.Namespace,
			hostNS.Pod.Name,
			"",
			[]string{"curl", "-s", fmt.Sprintf("http://localhost:%s/config_dump", ztunnelAdminPort)},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to execute curl in ztunnel pod: %w", err)
		}

		var config ztunnelDumpConfig
		if err := json.Unmarshal(stdout.Bytes(), &config); err != nil {
			return nil, fmt.Errorf("failed to parse ztunnel dump_config JSON: %w", err)
		}

		return config.Workloads, nil
	}

	validated := false
	for ctx.Err() == nil {
		clientWorkloads, err := fetchWorkloads(s.clientHostNS)
		if err != nil {
			t.Fatalf("Failed to fetch workloads from client ztunnel: %v", err)
		}

		// Check for enrolled client
		if s.config.clientEnrollment == Enrolled {
			found := false
			for _, wl := range clientWorkloads {
				if wl.UID == string(s.client.Pod.UID) {
					found = true
					break
				}
			}
			if !found {
				t.Debugf("Client ztunnel missing client workload, retrying")
				time.Sleep(1 * time.Second)
				continue
			}
		}

		// Check for enrolled server
		if s.config.serverEnrollment == Enrolled {
			found := false
			for _, wl := range clientWorkloads {
				if wl.UID == string(s.server.Pod.UID) {
					found = true
					break
				}
			}
			if !found {
				t.Debugf("Client ztunnel missing server workload, retrying")
				time.Sleep(1 * time.Second)
				continue
			}
		}

		validated = true
		break
	}

	if !validated {
		t.Fatalf("Timed out waiting for ztunnel workload information")
	}
	t.Debugf("Ztunnel workload validation complete")
}

// ================================================================================
// SPIRE Server Validation
// ================================================================================

// spiffeID represents a SPIFFE ID in the SPIRE server entry list output
type spiffeID struct {
	TrustDomain string `json:"trust_domain"`
	Path        string `json:"path"`
}

func (s *spiffeID) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", s.TrustDomain, s.Path)
}

// spireSelector represents a selector in the SPIRE server entry list output
type spireSelector struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// spireEntry represents an entry in the SPIRE server entry list output
type spireEntry struct {
	ID        string          `json:"id"`
	SpiffeID  *spiffeID       `json:"spiffe_id"`
	ParentID  *spiffeID       `json:"parent_id"`
	Selectors []spireSelector `json:"selectors"`
}

// spireEntryList represents the output of spire-server entry show -output json
type spireEntryList struct {
	Entries []spireEntry `json:"entries"`
}

// waitForSpireServerReady validates that SPIRE server has registered SPIFFE identities
// for all required components before running traffic tests.
//
// Required SPIFFE IDs:
// - spire-agent: SPIRE's workload attestor running on each node
// - cilium-agent: Cilium agent identity for ztunnel integration
// - cilium-operator: Cilium operator identity
// - ztunnel: Ztunnel proxy identity for handling mTLS connections
// - Enrolled pod service accounts: Each enrolled pod gets a SPIFFE ID based on its service account
//
// Without these SPIRE entries, mTLS certificate issuance will fail and ztunnel cannot
// establish encrypted tunnels between enrolled workloads.
func (s *ztunnelTestBase) waitForSpireServerReady(ctx context.Context, t *check.Test) {
	// Skip if no enrolled pods
	if s.config.clientEnrollment == Unenrolled && s.config.serverEnrollment == Unenrolled {
		t.Debugf("Skipping SPIRE server validation - no enrolled pods")
		return
	}

	var client *k8s.Client
	for _, c := range s.ct.Clients() {
		client = c
		break
	}
	if client == nil {
		t.Fatalf("No Kubernetes client available")
	}

	requiredSpiffeIDs := map[string]string{
		"spire-agent":     fmt.Sprintf("spiffe://%s/ns/%s/sa/spire-agent", spireTrustDomain, spireNamespace),
		"cilium-agent":    fmt.Sprintf("spiffe://%s/cilium-agent", spireTrustDomain),
		"cilium-operator": fmt.Sprintf("spiffe://%s/cilium-operator", spireTrustDomain),
		"ztunnel":         fmt.Sprintf("spiffe://%s/ztunnel", spireTrustDomain),
	}

	// Add enrolled pod service accounts to required list
	if s.config.clientEnrollment == Enrolled {
		clientSA := s.client.Pod.Spec.ServiceAccountName
		clientNS := s.client.Pod.Namespace
		requiredSpiffeIDs["client-sa"] = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", spireTrustDomain, clientNS, clientSA)
	}

	if s.config.serverEnrollment == Enrolled {
		serverSA := s.server.Pod.Spec.ServiceAccountName
		serverNS := s.server.Pod.Namespace
		requiredSpiffeIDs["server-sa"] = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", spireTrustDomain, serverNS, serverSA)
	}

	t.Debugf("Required SPIFFE IDs:")
	for name, spiffeID := range requiredSpiffeIDs {
		t.Debugf("  - %s: %s", name, spiffeID)
	}

	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	validated := false
	retryCount := 0
	for pollCtx.Err() == nil {
		retryCount++

		spireServerPod, err := client.GetPod(pollCtx, spireNamespace, spireServerPodName, metav1.GetOptions{})
		if err != nil {
			t.Debugf("SPIRE server pod not found yet: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if spireServerPod.Status.Phase != "Running" {
			t.Debugf("SPIRE server pod not running (phase: %s)", spireServerPod.Status.Phase)
			time.Sleep(2 * time.Second)
			continue
		}

		stdout, err := client.ExecInPod(
			pollCtx,
			spireNamespace,
			spireServerPodName,
			"spire-server",
			[]string{"/opt/spire/bin/spire-server", "entry", "show", "-output", "json"},
		)
		if err != nil {
			t.Debugf("Failed to execute spire-server entry show: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		var entryList spireEntryList
		if err := json.Unmarshal(stdout.Bytes(), &entryList); err != nil {
			t.Debugf("Failed to parse SPIRE entry list JSON: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		availableSpiffeIDs := make(map[string]bool)
		for _, entry := range entryList.Entries {
			if entry.SpiffeID != nil {
				availableSpiffeIDs[entry.SpiffeID.String()] = true
			}
		}

		// Check which entries are found and which are missing
		var found []string
		var missing []string
		for name, spiffeID := range requiredSpiffeIDs {
			if availableSpiffeIDs[spiffeID] {
				found = append(found, fmt.Sprintf("%s (%s)", name, spiffeID))
			} else {
				missing = append(missing, fmt.Sprintf("%s (%s)", name, spiffeID))
			}
		}

		if len(missing) > 0 {
			t.Debugf("SPIRE entries check (attempt %d):", retryCount)
			t.Debugf("  Found %d/%d required entries:", len(found), len(requiredSpiffeIDs))
			for _, f := range found {
				t.Debugf("    ✓ %s", f)
			}
			t.Debugf("  Missing %d entries:", len(missing))
			for _, m := range missing {
				t.Debugf("    ✗ %s", m)
			}

			// Log all available SPIFFE IDs for debugging
			if retryCount%5 == 0 { // Only log every 5th attempt to reduce noise
				t.Debugf("  All available SPIFFE IDs in SPIRE server (%d total):", len(availableSpiffeIDs))
				for spiffeID := range availableSpiffeIDs {
					t.Debugf("    - %s", spiffeID)
				}
			}

			time.Sleep(2 * time.Second)
			continue
		}

		validated = true
		t.Debugf("All %d required SPIRE entries found after %d attempts", len(requiredSpiffeIDs), retryCount)
		break
	}

	if !validated {
		t.Fatalf("Timed out waiting for SPIRE server entries after %d attempts", retryCount)
	}

	t.Infof("✓ SPIRE server ready with required entries")
}

// ================================================================================
// Namespace Enrollment Management
// ================================================================================

// enrollNamespace adds the mtls-enabled label to a namespace to enroll it in ztunnel mTLS.
// This triggers Cilium to create SPIRE entries for workloads in this namespace.
func (s *ztunnelTestBase) enrollNamespace(ctx context.Context, t *check.Test, namespace string) error {
	t.Debugf("Enrolling namespace %s in ztunnel mTLS", namespace)

	ns, err := s.ct.K8sClient().GetNamespace(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", namespace, err)
	}

	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}
	ns.Labels[mtlsEnabledLabel] = "true"

	_, err = s.ct.K8sClient().Clientset.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update namespace %s with enrollment label: %w", namespace, err)
	}

	t.Debugf("✓ Namespace %s enrolled", namespace)
	return nil
}

// disenrollNamespace removes the mtls-enabled label from a namespace to disenroll it from ztunnel mTLS.
// This triggers Cilium to remove SPIRE entries for workloads in this namespace.
func (s *ztunnelTestBase) disenrollNamespace(ctx context.Context, t *check.Test, namespace string) error {
	t.Debugf("Disenrolling namespace %s from ztunnel mTLS", namespace)

	ns, err := s.ct.K8sClient().GetNamespace(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", namespace, err)
	}

	if ns.Labels != nil {
		delete(ns.Labels, mtlsEnabledLabel)
	}

	_, err = s.ct.K8sClient().Clientset.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update namespace %s to remove enrollment label: %w", namespace, err)
	}

	t.Debugf("✓ Namespace %s disenrolled", namespace)
	return nil
}

// waitForSpireEntriesRemoved validates that SPIRE server has removed entries for disenrolled pods.
// This ensures cleanup happens correctly when namespaces are disenrolled.
func (s *ztunnelTestBase) waitForSpireEntriesRemoved(ctx context.Context, t *check.Test, expectedRemovedSpiffeIDs map[string]string) {
	if len(expectedRemovedSpiffeIDs) == 0 {
		t.Debugf("No SPIRE entries expected to be removed")
		return
	}

	var client *k8s.Client
	for _, c := range s.ct.Clients() {
		client = c
		break
	}
	if client == nil {
		t.Fatalf("No Kubernetes client available")
	}

	t.Debugf("Expected removed SPIFFE IDs:")
	for name, spiffeID := range expectedRemovedSpiffeIDs {
		t.Debugf("  - %s: %s", name, spiffeID)
	}

	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	validated := false
	retryCount := 0
	for pollCtx.Err() == nil {
		retryCount++

		spireServerPod, err := client.GetPod(pollCtx, spireNamespace, spireServerPodName, metav1.GetOptions{})
		if err != nil {
			t.Debugf("SPIRE server pod not found: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if spireServerPod.Status.Phase != "Running" {
			t.Debugf("SPIRE server pod not running (phase: %s)", spireServerPod.Status.Phase)
			time.Sleep(2 * time.Second)
			continue
		}

		stdout, err := client.ExecInPod(
			pollCtx,
			spireNamespace,
			spireServerPodName,
			"spire-server",
			[]string{"/opt/spire/bin/spire-server", "entry", "show", "-output", "json"},
		)
		if err != nil {
			t.Debugf("Failed to execute spire-server entry show: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		var entryList spireEntryList
		if err := json.Unmarshal(stdout.Bytes(), &entryList); err != nil {
			t.Debugf("Failed to parse SPIRE entry list JSON: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		availableSpiffeIDs := make(map[string]bool)
		for _, entry := range entryList.Entries {
			if entry.SpiffeID != nil {
				availableSpiffeIDs[entry.SpiffeID.String()] = true
			}
		}

		// Check if any of the expected removed entries still exist
		var stillPresent []string
		for name, spiffeID := range expectedRemovedSpiffeIDs {
			if availableSpiffeIDs[spiffeID] {
				stillPresent = append(stillPresent, fmt.Sprintf("%s (%s)", name, spiffeID))
			}
		}

		if len(stillPresent) > 0 {
			t.Debugf("SPIRE cleanup check (attempt %d): %d entries still present", retryCount, len(stillPresent))
			for _, p := range stillPresent {
				t.Debugf("  ✗ Still present: %s", p)
			}
			time.Sleep(2 * time.Second)
			continue
		}

		validated = true
		t.Debugf("All %d expected SPIRE entries removed after %d attempts", len(expectedRemovedSpiffeIDs), retryCount)
		break
	}

	if !validated {
		t.Fatalf("Timed out waiting for SPIRE entries to be removed after %d attempts", retryCount)
	}

	t.Infof("✓ SPIRE entries successfully removed")
}

// ================================================================================
// Traffic Filters and Sniffers
// ================================================================================

// createTrafficFiltersForFamily creates tcpdump filters for a specific IP family and port.
// For same-node scenarios, it creates bidirectional filters since both pods share the same host network.
// For different-node scenarios, it creates separate client and server filters for directional traffic.
func createTrafficFiltersForFamily(clientIP, serverIP, suffix string, port int, sameNode bool) map[string]string {
	filters := make(map[string]string)

	if sameNode {
		// Same node: bidirectional traffic filter
		filters["client-"+suffix] = fmt.Sprintf(
			"tcp and port %d and ((src host %s and dst host %s) or (src host %s and dst host %s))",
			port, clientIP, serverIP, serverIP, clientIP)
	} else {
		// Different nodes: outbound from client
		filters["client-"+suffix] = fmt.Sprintf(
			"tcp and dst port %d and src host %s and dst host %s",
			port, clientIP, serverIP)
		// Different nodes: inbound to server
		filters["server-"+suffix] = fmt.Sprintf(
			"tcp and dst port %d and src host %s and dst host %s",
			port, clientIP, serverIP)
	}

	return filters
}

// createTrafficFilters creates tcpdump filters for encrypted and plain text traffic.
//
// We create two sets of filters to prove encryption:
// 1. Encrypted filters: Detect traffic on port 15008 (ztunnel HBONE proxy port)
// 2. Plain text filters: Detect traffic on port 8080 (direct HTTP to echo server)
//
// Based on enrollment status, tests assert:
// - Enrolled→Enrolled: MUST see port 15008, MUST NOT see port 8080
// - Other scenarios: MUST NOT see port 15008, MUST see port 8080
func (s *ztunnelTestBase) createTrafficFilters() (encrypted, plainText map[string]string, err error) {
	encrypted = make(map[string]string)
	plainText = make(map[string]string)

	sameNode := s.clientHostNS.Pod.Name == s.serverHostNS.Pod.Name

	if s.ipv4Enabled.Enabled {
		clientIPv4 := s.client.Address(features.IPFamilyV4)
		serverIPv4 := s.server.Address(features.IPFamilyV4)

		// Create filters for encrypted traffic (port 15008)
		maps.Copy(encrypted, createTrafficFiltersForFamily(clientIPv4, serverIPv4, "ipv4", ztunnelInboundPort, sameNode))

		// Create filters for plain text traffic (port 8080)
		maps.Copy(plainText, createTrafficFiltersForFamily(clientIPv4, serverIPv4, "ipv4", echoServerPort, sameNode))
	}

	if s.ipv6Enabled.Enabled {
		clientIPv6 := s.client.Address(features.IPFamilyV6)
		serverIPv6 := s.server.Address(features.IPFamilyV6)

		// Create filters for encrypted traffic (port 15008)
		maps.Copy(encrypted, createTrafficFiltersForFamily(clientIPv6, serverIPv6, "ipv6", ztunnelInboundPort, sameNode))

		// Create filters for plain text traffic (port 8080)
		maps.Copy(plainText, createTrafficFiltersForFamily(clientIPv6, serverIPv6, "ipv6", echoServerPort, sameNode))
	}

	return encrypted, plainText, nil
}

// startSnifferForFamily starts tcpdump sniffers for a specific IP family.
// Returns a map of sniffers keyed by "client-<suffix>" and "server-<suffix>".
// For same-node scenarios, the server sniffer reuses the client sniffer since both pods
// share the same host network namespace.
func (s *ztunnelTestBase) startSnifferForFamily(ctx context.Context, t *check.Test, mode sniff.Mode,
	filters map[string]string, name, suffix string, sameNode bool,
) (map[string]*sniff.Sniffer, error) {
	sniffers := make(map[string]*sniff.Sniffer)
	captureInterface := "any"

	clientKey := "client-" + suffix
	serverKey := "server-" + suffix
	clientFilter := filters[clientKey]
	serverFilter := filters[serverKey]

	// Start client sniffer (always needed)
	if clientFilter != "" {
		sniffer, cancel, err := sniff.Sniff(ctx, name, s.clientHostNS, captureInterface, clientFilter, mode, sniff.SniffKillTimeout, t)
		if err != nil {
			return nil, fmt.Errorf("failed to start client sniffer for %s: %w", suffix, err)
		}
		s.finalizers = append(s.finalizers, cancel)
		sniffers[clientKey] = sniffer
	}

	// Start server sniffer only if on different node
	if !sameNode && serverFilter != "" {
		sniffer, cancel, err := sniff.Sniff(ctx, name, s.serverHostNS, captureInterface, serverFilter, mode, sniff.SniffKillTimeout, t)
		if err != nil {
			return nil, fmt.Errorf("failed to start server sniffer for %s: %w", suffix, err)
		}
		s.finalizers = append(s.finalizers, cancel)
		sniffers[serverKey] = sniffer
	} else if sameNode && serverFilter != "" {
		// For same node, reuse the client sniffer for server validation.
		// This works because both pods are on the same node and share the host network namespace,
		// so a single capture point sees traffic in both directions.
		sniffers[serverKey] = sniffers[clientKey]
	}

	return sniffers, nil
}

// startSniffers starts tcpdump on both client and server host network pods
func (s *ztunnelTestBase) startSniffers(ctx context.Context, t *check.Test, mode sniff.Mode, filters map[string]string, name string) (map[string]*sniff.Sniffer, error) {
	allSniffers := make(map[string]*sniff.Sniffer)

	// Check if client and server are on the same node (same host network pod)
	sameNode := s.clientHostNS.Pod.Name == s.serverHostNS.Pod.Name

	if s.ipv4Enabled.Enabled {
		sniffers, err := s.startSnifferForFamily(ctx, t, mode, filters, name, "ipv4", sameNode)
		if err != nil {
			return nil, err
		}
		maps.Copy(allSniffers, sniffers)
	}

	if s.ipv6Enabled.Enabled {
		nameIPv6 := fmt.Sprintf("%s-ipv6", name)
		sniffers, err := s.startSnifferForFamily(ctx, t, mode, filters, nameIPv6, "ipv6", sameNode)
		if err != nil {
			return nil, err
		}
		maps.Copy(allSniffers, sniffers)
	}

	return allSniffers, nil
}

// ================================================================================
// Traffic Generation and Validation
// ================================================================================

// executeTrafficTest performs curl from client to server with retry and validates sniffers
func (s *ztunnelTestBase) executeTrafficTest(ctx context.Context, t *check.Test,
	encryptedSniffers, plainTextSniffers map[string]*sniff.Sniffer,
) {
	if s.ipv4Enabled.Enabled {
		s.executeTrafficForIPFamily(ctx, t, features.IPFamilyV4,
			encryptedSniffers, plainTextSniffers)
	}

	if s.ipv6Enabled.Enabled {
		s.executeTrafficForIPFamily(ctx, t, features.IPFamilyV6,
			encryptedSniffers, plainTextSniffers)
	}
}

// executeTrafficForIPFamily performs curl and validates sniffers for a specific IP family
func (s *ztunnelTestBase) executeTrafficForIPFamily(ctx context.Context, t *check.Test, ipFamily features.IPFamily,
	encryptedSniffers, plainTextSniffers map[string]*sniff.Sniffer,
) {
	var url string
	if ipFamily == features.IPFamilyV4 {
		url = fmt.Sprintf("http://%s:%d/", s.server.Address(ipFamily), echoServerPort)
	} else {
		url = fmt.Sprintf("http://[%s]:%d/", s.server.Address(ipFamily), echoServerPort)
	}

	// Retry loop for curl command
	var lastErr error
	for attempt := 1; attempt <= maxCurlRetries; attempt++ {
		if attempt > 1 {
			t.Debugf("Retry attempt %d/%d...", attempt, maxCurlRetries)
			time.Sleep(curlRetryDelay)
		}

		output, err := s.client.K8sClient.ExecInPod(ctx,
			s.client.Pod.Namespace, s.client.Pod.Name, s.client.Pod.Labels["name"],
			[]string{"curl", "-sS", "--fail", "--connect-timeout", "5", "--max-time", "10", url})

		if err == nil && output.Len() > 0 {
			t.Debugf("✓ Curl succeeded on attempt %d", attempt)
			lastErr = nil
			break
		}

		lastErr = err
	}

	if lastErr != nil {
		t.Fatalf("Curl failed after %d attempts: %v", maxCurlRetries, lastErr)
	}

	// Validate sniffers
	suffix := "ipv4"
	if ipFamily == features.IPFamilyV6 {
		suffix = "ipv6"
	}

	action := t.NewAction(s, fmt.Sprintf("curl-%s", ipFamily), s.client, s.server, ipFamily)
	action.Run(func(a *check.Action) {
		// Track validated sniffers to avoid validating the same sniffer twice
		validated := make(map[*sniff.Sniffer]bool)

		// Validate encrypted traffic sniffers (port 15008)
		if sniffer, ok := encryptedSniffers["client-"+suffix]; ok && sniffer != nil && !validated[sniffer] {
			t.Debugf("[%s] Validating encrypted traffic sniffer: client-%s", ipFamily, suffix)
			sniffer.Validate(a)
			validated[sniffer] = true
		}
		if sniffer, ok := encryptedSniffers["server-"+suffix]; ok && sniffer != nil && !validated[sniffer] {
			t.Debugf("[%s] Validating encrypted traffic sniffer: server-%s", ipFamily, suffix)
			sniffer.Validate(a)
			validated[sniffer] = true
		}

		// Validate plain text traffic sniffers (port 8080)
		if sniffer, ok := plainTextSniffers["client-"+suffix]; ok && sniffer != nil && !validated[sniffer] {
			t.Debugf("[%s] Validating plain text traffic sniffer: client-%s", ipFamily, suffix)
			sniffer.Validate(a)
			validated[sniffer] = true
		}
		if sniffer, ok := plainTextSniffers["server-"+suffix]; ok && sniffer != nil && !validated[sniffer] {
			t.Debugf("[%s] Validating plain text traffic sniffer: server-%s", ipFamily, suffix)
			sniffer.Validate(a)
			validated[sniffer] = true
		}
	})
}

// ================================================================================
// Daemonset Wait Helper
// ================================================================================

// waitOnZTunnelDS waits for the ztunnel daemonset to be ready
func (s *ztunnelTestBase) waitOnZTunnelDS(ctx context.Context, t *check.Test) {
	if err := check.WaitForDaemonSet(ctx, t, s.ct.K8sClient(), s.namespace, "ztunnel-cilium"); err != nil {
		t.Fatalf("Failed to wait for ztunnel-cilium daemonset: %s", err)
	}
}

// ================================================================================
// Main Test Run Method
// ================================================================================

func (s *ztunnelTestBase) Run(ctx context.Context, t *check.Test) {
	s.ct = t.Context()
	s.namespace = s.ct.Params().CiliumNamespace

	// Cleanup on exit
	defer func() {
		for _, f := range s.finalizers {
			if err := f(); err != nil {
				t.Debugf("Failed to run finalizer: %v", err)
			}
		}
	}()

	// Get feature flags
	var ok bool
	s.ipv4Enabled, ok = s.ct.Feature(features.IPv4)
	if !ok {
		t.Fatalf("Failed to detect IPv4 feature")
	}
	s.ipv6Enabled, ok = s.ct.Feature(features.IPv6)
	if !ok {
		t.Fatalf("Failed to detect IPv6 feature")
	}
	s.encryptMode, ok = s.ct.Feature(features.EncryptionPod)
	if !ok {
		t.Fatalf("Failed to detect encryption mode")
	}

	if !s.ipv4Enabled.Enabled && !s.ipv6Enabled.Enabled {
		t.Fatalf("Test requires at least one IP family to be enabled")
	}

	t.Infof("==== Ztunnel Scenario: %s ====", s.config.name)
	t.Infof("Configuration: client=%s, server=%s, location=%v, expectEncryption=%v",
		enrollmentName(s.config.clientEnrollment),
		enrollmentName(s.config.serverEnrollment),
		locationName(s.config.location),
		s.config.expectEncryption)

	// Setup
	s.waitOnZTunnelDS(ctx, t)
	s.setupTestPods(ctx, t)

	// Dynamically enroll namespaces based on test configuration
	// All namespaces start unenrolled, we label them here to enroll
	namespacesToEnroll := make(map[string]bool)
	namespacesToDisenroll := make([]string, 0)

	if s.config.clientEnrollment == Enrolled {
		ns := s.client.Pod.Namespace
		if !namespacesToEnroll[ns] {
			t.Infof("Enrolling client namespace: %s", ns)
			if err := s.enrollNamespace(ctx, t, ns); err != nil {
				t.Fatalf("Failed to enroll client namespace %s: %v", ns, err)
			}
			namespacesToEnroll[ns] = true
			namespacesToDisenroll = append(namespacesToDisenroll, ns)
		}
	}

	if s.config.serverEnrollment == Enrolled {
		ns := s.server.Pod.Namespace
		if !namespacesToEnroll[ns] {
			t.Infof("Enrolling server namespace: %s", ns)
			if err := s.enrollNamespace(ctx, t, ns); err != nil {
				t.Fatalf("Failed to enroll server namespace %s: %v", ns, err)
			}
			namespacesToEnroll[ns] = true
			namespacesToDisenroll = append(namespacesToDisenroll, ns)
		}
	}

	// Add cleanup to disenroll namespaces at the end of the test
	defer func() {
		if len(namespacesToDisenroll) > 0 {
			t.Infof("Cleaning up: disenrolling %d namespace(s)", len(namespacesToDisenroll))

			// Track SPIRE entries that should be removed
			expectedRemovedSpiffeIDs := make(map[string]string)

			if s.config.clientEnrollment == Enrolled {
				clientSA := s.client.Pod.Spec.ServiceAccountName
				clientNS := s.client.Pod.Namespace
				expectedRemovedSpiffeIDs["client-sa"] = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", spireTrustDomain, clientNS, clientSA)
			}

			if s.config.serverEnrollment == Enrolled {
				serverSA := s.server.Pod.Spec.ServiceAccountName
				serverNS := s.server.Pod.Namespace
				expectedRemovedSpiffeIDs["server-sa"] = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", spireTrustDomain, serverNS, serverSA)
			}

			// Disenroll all namespaces
			for _, ns := range namespacesToDisenroll {
				t.Debugf("Disenrolling namespace: %s", ns)
				if err := s.disenrollNamespace(ctx, t, ns); err != nil {
					t.Debugf("Failed to disenroll namespace %s: %v", ns, err)
				}
			}

			// Wait for SPIRE entries to be removed
			s.waitForSpireEntriesRemoved(ctx, t, expectedRemovedSpiffeIDs)
		}
	}()

	s.getHostNSPods(t)
	s.getZTunnelPods(ctx, t)

	// Validate prerequisites - SPIRE entries should now be created
	s.waitForSpireServerReady(ctx, t)

	timeout, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	s.validateZTunnelState(timeout, t)

	// Create traffic filters
	encryptedFilters, plainTextFilters, err := s.createTrafficFilters()
	if err != nil {
		t.Fatalf("Failed to create traffic filters: %v", err)
	}

	// Determine sniffer modes based on expected encryption
	var encryptedMode, plainTextMode sniff.Mode
	if s.config.expectEncryption {
		// When encryption is expected:
		// - encrypted traffic (port 15008) should be present (ModeSanity)
		// - plain text traffic (port 8080) should NOT be present (ModeAssert)
		encryptedMode = sniff.ModeSanity
		plainTextMode = sniff.ModeAssert
		t.Info("Expecting encrypted traffic on port 15008, no plain text on port 8080")
	} else {
		// When encryption is NOT expected:
		// - encrypted traffic (port 15008) should NOT be present (ModeAssert)
		// - plain text traffic (port 8080) should be present (ModeSanity)
		encryptedMode = sniff.ModeAssert
		plainTextMode = sniff.ModeSanity
		t.Info("Expecting plain text traffic on port 8080, no encrypted traffic on port 15008")
	}

	// Start sniffers for encrypted traffic (port 15008)
	encryptedSniffers, err := s.startSniffers(ctx, t, encryptedMode, encryptedFilters, "ztunnel-encrypted")
	if err != nil {
		t.Fatalf("Failed to start encrypted traffic sniffers: %s", err)
	}

	// Start sniffers for plain text traffic (port 8080)
	plainTextSniffers, err := s.startSniffers(ctx, t, plainTextMode, plainTextFilters, "ztunnel-plaintext")
	if err != nil {
		t.Fatalf("Failed to start plain text traffic sniffers: %s", err)
	}

	// Execute traffic test
	t.Info("Sending HTTP request...")
	s.executeTrafficTest(ctx, t, encryptedSniffers, plainTextSniffers)

	t.Info("✓ Test complete")
}

// ================================================================================
// Helper Functions
// ================================================================================

func enrollmentName(e enrollmentStatus) string {
	if e == Enrolled {
		return "enrolled"
	}
	return "unenrolled"
}

func locationName(l podLocation) string {
	if l == SameNode {
		return "same-node"
	}
	return "different-node"
}
