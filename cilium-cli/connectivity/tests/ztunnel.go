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
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
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
	maxCurlRetries      = 5
	curlRetryDelay      = 2 * time.Second

	// Namespace enrollment label for Cilium's ztunnel mTLS
	mtlsEnabledLabel = "io.cilium/mtls-enabled"
)

// podLocation defines whether pods are on the same or different nodes
type podLocation int

const (
	sameNode podLocation = iota
	differentNode
)

// enrollmentStatus defines whether a pod is enrolled in ztunnel mTLS
type enrollmentStatus int

const (
	enrolled enrollmentStatus = iota
	unenrolled
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
	client check.Pod
	server check.Pod

	// host network namespace pods
	clientHostNS check.Pod
	serverHostNS check.Pod

	// feature flags
	ipv4Enabled features.Status
	ipv6Enabled features.Status

	// finalizers to clean up resources
	finalizers []func() error
}

// ZTunnelEnrolledToEnrolledSameNode tests mTLS encryption between enrolled pods on same node
func ZTunnelEnrolledToEnrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-same-node",
		clientEnrollment: enrolled,
		serverEnrollment: enrolled,
		location:         sameNode,
		sameNamespace:    true,
		expectEncryption: true,
	})
}

// ZTunnelEnrolledToEnrolledDifferentNode tests mTLS encryption between enrolled pods on different nodes
func ZTunnelEnrolledToEnrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-different-node",
		clientEnrollment: enrolled,
		serverEnrollment: enrolled,
		location:         differentNode,
		sameNamespace:    true,
		expectEncryption: true,
	})
}

// ZTunnelUnenrolledToUnenrolledSameNode tests plain traffic between unenrolled pods on same node
func ZTunnelUnenrolledToUnenrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-unenrolled-same-node",
		clientEnrollment: unenrolled,
		serverEnrollment: unenrolled,
		location:         sameNode,
		sameNamespace:    true,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToUnenrolledDifferentNode tests plain traffic between unenrolled pods on different nodes
func ZTunnelUnenrolledToUnenrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-unenrolled-different-node",
		clientEnrollment: unenrolled,
		serverEnrollment: unenrolled,
		location:         differentNode,
		sameNamespace:    true,
		expectEncryption: false,
	})
}

// ZTunnelEnrolledToUnenrolledSameNode tests plain traffic from enrolled client to unenrolled server on same node
func ZTunnelEnrolledToUnenrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-unenrolled-same-node",
		clientEnrollment: enrolled,
		serverEnrollment: unenrolled,
		location:         sameNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelEnrolledToUnenrolledDifferentNode tests plain traffic from enrolled client to unenrolled server on different nodes
func ZTunnelEnrolledToUnenrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-unenrolled-different-node",
		clientEnrollment: enrolled,
		serverEnrollment: unenrolled,
		location:         differentNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToEnrolledSameNode tests plain traffic from unenrolled client to enrolled server on same node
func ZTunnelUnenrolledToEnrolledSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-enrolled-same-node",
		clientEnrollment: unenrolled,
		serverEnrollment: enrolled,
		location:         sameNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelUnenrolledToEnrolledDifferentNode tests plain traffic from unenrolled client to enrolled server on different nodes
func ZTunnelUnenrolledToEnrolledDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "unenrolled-to-enrolled-different-node",
		clientEnrollment: unenrolled,
		serverEnrollment: enrolled,
		location:         differentNode,
		sameNamespace:    false,
		expectEncryption: false,
	})
}

// ZTunnelEnrolledToEnrolledCrossNamespaceSameNode tests mTLS between enrolled pods in different namespaces on same node
func ZTunnelEnrolledToEnrolledCrossNamespaceSameNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-cross-ns-same-node",
		clientEnrollment: enrolled,
		serverEnrollment: enrolled,
		location:         sameNode,
		sameNamespace:    false,
		expectEncryption: true,
	})
}

// ZTunnelEnrolledToEnrolledCrossNamespaceDifferentNode tests mTLS between enrolled pods in different namespaces on different nodes
func ZTunnelEnrolledToEnrolledCrossNamespaceDifferentNode() check.Scenario {
	return newZTunnelTest(scenarioConfig{
		name:             "enrolled-to-enrolled-cross-ns-different-node",
		clientEnrollment: enrolled,
		serverEnrollment: enrolled,
		location:         differentNode,
		sameNamespace:    false,
		expectEncryption: true,
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

// getNamespaceForEnrollment determines which namespace to use based on enrollment and pod type.
//
// Namespace distribution strategy:
// - All 3 test namespaces (enrolled-0, enrolled-1, unenrolled) start without the mtls-enabled label
// - During test execution, namespaces are dynamically labeled based on enrollment requirements
// - unenrolled pods use "cilium-test-ztunnel-unenrolled"
// - enrolled pods in same-namespace tests use "cilium-test-ztunnel-enrolled-0"
// - enrolled pods in cross-namespace tests:
//   - Client pods → "cilium-test-ztunnel-enrolled-0"
//   - Server pods → "cilium-test-ztunnel-enrolled-1"
//
// This ensures we test both intra-namespace and inter-namespace mTLS scenarios.
func (s *ztunnelTestBase) getNamespaceForEnrollment(enrollment enrollmentStatus, podType string) string {
	if enrollment == unenrolled {
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
// - sameNode: Pod must be on the same node as referenceNode
// - differentNode: Pod must be on a different node than referenceNode
func (s *ztunnelTestBase) getPod(ctx context.Context, t *check.Test, enrollment enrollmentStatus, podType string, referenceNode string, location podLocation) check.Pod {
	namespace := s.getNamespaceForEnrollment(enrollment, podType)

	// Determine label selector based on podType
	// For echo pods, use the full deployment name
	labelSelector := "name=client"
	if podType != "client" {
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
	pod := filterPodsByLocation(pods.Items, referenceNode, location)
	if pod == nil {
		t.Fatalf("Failed to find %s pod matching node location requirements in namespace %s (selector: %s, referenceNode: %s, location: %s, found %d pods)",
			podType, namespace, labelSelector, referenceNode, locationName(location), len(pods.Items))
	}

	return check.Pod{
		K8sClient: s.ct.K8sClient(),
		Pod:       pod,
	}
}

// filterPodsByLocation finds the first pod matching the specified node location constraint.
// Returns nil if no matching pod is found.
func filterPodsByLocation(pods []corev1.Pod, referenceNode string, location podLocation) *corev1.Pod {
	for i := range pods {
		pod := &pods[i]
		if referenceNode == "" {
			return pod
		}
		if location == sameNode && pod.Spec.NodeName == referenceNode {
			return pod
		}
		if location == differentNode && pod.Spec.NodeName != referenceNode {
			return pod
		}
	}
	return nil
}

// setupTestPods configures client and server pods based on test configuration
func (s *ztunnelTestBase) setupTestPods(ctx context.Context, t *check.Test) {
	// Get client pod
	s.client = s.getPod(ctx, t, s.config.clientEnrollment, "client", "", sameNode)

	// Get server pod based on location and enrollment
	serverPodType := "echo-same-node"
	if s.config.location == differentNode {
		serverPodType = "echo-other-node"
	}

	s.server = s.getPod(ctx, t, s.config.serverEnrollment, serverPodType, s.client.Pod.Spec.NodeName, s.config.location)

	t.Debugf("Selected pods: client=%s (node=%s, ns=%s), server=%s (node=%s, ns=%s)",
		s.client.Pod.Name, s.client.Pod.Spec.NodeName, s.client.Pod.Namespace,
		s.server.Pod.Name, s.server.Pod.Spec.NodeName, s.server.Pod.Namespace)
}

// assignHostNSPods acquires host namespace pods for packet capture on client and server nodes.
//
// Ztunnel runs as a DaemonSet in the host network namespace, so encrypted traffic between
// nodes flows through the host network stack, not the pod network. To capture this traffic
// with tcpdump, we need pods with:
// 1. Host network access (hostNetwork: true)
// 2. NET_ADMIN capability to run tcpdump
//
// These host network pods are deployed by the connectivity test framework.
func (s *ztunnelTestBase) assignHostNSPods(t *check.Test) {
	clientHostNS, ok := s.ct.HostNetNSPodsByNode()[s.client.Pod.Spec.NodeName]
	if !ok {
		t.Fatalf("Failed to acquire host namespace pod on %s (client's node)", s.client.Pod.Spec.NodeName)
	}
	s.clientHostNS = clientHostNS

	serverHostNS, ok := s.ct.HostNetNSPodsByNode()[s.server.Pod.Spec.NodeName]
	if !ok {
		t.Fatalf("Failed to acquire host namespace pod on %s (server's node)", s.server.Pod.Spec.NodeName)
	}
	s.serverHostNS = serverHostNS
}

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
	if s.config.clientEnrollment == unenrolled && s.config.serverEnrollment == unenrolled {
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

	hasWorkload := func(workloads []workload, uid string) bool {
		for _, wl := range workloads {
			if wl.UID == uid {
				return true
			}
		}
		return false
	}

	sameNode := s.clientHostNS.Pod.Name == s.serverHostNS.Pod.Name

	validated := false
	for ctx.Err() == nil {
		// Fetch workloads from client's ztunnel
		clientWorkloads, err := fetchWorkloads(&s.clientHostNS)
		if err != nil {
			t.Fatalf("Failed to fetch workloads from client ztunnel: %v", err)
		}

		// Check client ztunnel has enrolled client workload
		if s.config.clientEnrollment == enrolled {
			if !hasWorkload(clientWorkloads, string(s.client.Pod.UID)) {
				t.Debugf("Client ztunnel missing client workload, retrying")
				time.Sleep(1 * time.Second)
				continue
			}
		}

		// Check client ztunnel has enrolled server workload
		if s.config.serverEnrollment == enrolled {
			if !hasWorkload(clientWorkloads, string(s.server.Pod.UID)) {
				t.Debugf("Client ztunnel missing server workload, retrying")
				time.Sleep(1 * time.Second)
				continue
			}
		}

		// For different node scenarios, also validate server's ztunnel
		if !sameNode && s.config.serverEnrollment == enrolled {
			serverWorkloads, err := fetchWorkloads(&s.serverHostNS)
			if err != nil {
				t.Fatalf("Failed to fetch workloads from server ztunnel: %v", err)
			}

			if !hasWorkload(serverWorkloads, string(s.server.Pod.UID)) {
				t.Debugf("Server ztunnel missing server workload, retrying")
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

// enrollNamespace adds the mtls-enabled label to a namespace to enroll it in ztunnel mTLS.
func (s *ztunnelTestBase) enrollNamespace(ctx context.Context, t *check.Test, namespace string) error {
	t.Debugf("Enrolling namespace %s in ztunnel mTLS", namespace)

	patch := fmt.Appendf(nil, `{"metadata":{"labels":{"%s":"true"}}}`, mtlsEnabledLabel)
	_, err := s.ct.K8sClient().Clientset.CoreV1().Namespaces().Patch(
		ctx, namespace, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch namespace %s with enrollment label: %w", namespace, err)
	}

	t.Debugf("Namespace %s enrolled", namespace)
	return nil
}

// disenrollNamespace removes the mtls-enabled label from a namespace to disenroll it from ztunnel mTLS.
func (s *ztunnelTestBase) disenrollNamespace(ctx context.Context, t *check.Test, namespace string) error {
	t.Debugf("Disenrolling namespace %s from ztunnel mTLS", namespace)

	patch := fmt.Appendf(nil, `{"metadata":{"labels":{"%s":null}}}`, mtlsEnabledLabel)
	_, err := s.ct.K8sClient().Clientset.CoreV1().Namespaces().Patch(
		ctx, namespace, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch namespace %s to remove enrollment label: %w", namespace, err)
	}

	t.Debugf("Namespace %s disenrolled", namespace)
	return nil
}

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
// - enrolled→enrolled: MUST see port 15008, MUST NOT see port 8080
// - Other scenarios: MUST NOT see port 15008, MUST see port 8080
func (s *ztunnelTestBase) createTrafficFilters() (encrypted, plainText map[string]string) {
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

	return encrypted, plainText
}

// startSniffer starts a tcpdump sniffer on the given host network pod.
func (s *ztunnelTestBase) startSniffer(ctx context.Context, t *check.Test, mode sniff.Mode,
	hostNS *check.Pod, filter, name string,
) (*sniff.Sniffer, error) {
	sniffer, cancel, err := sniff.Sniff(ctx, name, hostNS, "any", filter, mode, sniff.SniffKillTimeout, t)
	if err != nil {
		return nil, err
	}
	s.finalizers = append(s.finalizers, cancel)
	return sniffer, nil
}

// startSnifferForFamily starts tcpdump sniffers for a specific IP family.
// Returns a map of sniffers keyed by "client-<suffix>" and "server-<suffix>".
// For same-node scenarios, the server sniffer reuses the client sniffer since both pods
// share the same host network namespace.
func (s *ztunnelTestBase) startSnifferForFamily(ctx context.Context, t *check.Test, mode sniff.Mode,
	filters map[string]string, name, suffix string, sameNode bool,
) (map[string]*sniff.Sniffer, error) {
	sniffers := make(map[string]*sniff.Sniffer)

	clientKey := "client-" + suffix
	serverKey := "server-" + suffix
	clientFilter := filters[clientKey]
	serverFilter := filters[serverKey]

	// Start client sniffer (always needed)
	if clientFilter != "" {
		sniffer, err := s.startSniffer(ctx, t, mode, &s.clientHostNS, clientFilter, name)
		if err != nil {
			return nil, fmt.Errorf("failed to start client sniffer for %s: %w", suffix, err)
		}
		sniffers[clientKey] = sniffer
	}

	// Start server sniffer only if on different node
	if !sameNode && serverFilter != "" {
		sniffer, err := s.startSniffer(ctx, t, mode, &s.serverHostNS, serverFilter, name)
		if err != nil {
			return nil, fmt.Errorf("failed to start server sniffer for %s: %w", suffix, err)
		}
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
			t.Debugf("Curl succeeded on attempt %d", attempt)
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

	action := t.NewAction(s, fmt.Sprintf("curl-%s", ipFamily), &s.client, &s.server, ipFamily)
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

// waitOnZTunnelDS waits for the ztunnel daemonset to be ready
func (s *ztunnelTestBase) waitOnZTunnelDS(ctx context.Context, t *check.Test) {
	if err := check.WaitForDaemonSet(ctx, t, s.ct.K8sClient(), s.namespace, "ztunnel-cilium"); err != nil {
		t.Fatalf("Failed to wait for ztunnel-cilium daemonset: %s", err)
	}
}

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

	if s.config.clientEnrollment == enrolled {
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

	if s.config.serverEnrollment == enrolled {
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

			// Disenroll all namespaces
			for _, ns := range namespacesToDisenroll {
				t.Debugf("Disenrolling namespace: %s", ns)
				if err := s.disenrollNamespace(ctx, t, ns); err != nil {
					t.Debugf("Failed to disenroll namespace %s: %v", ns, err)
				}
			}
		}
	}()

	s.assignHostNSPods(t)

	timeout, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	s.validateZTunnelState(timeout, t)

	// Create traffic filters
	encryptedFilters, plainTextFilters := s.createTrafficFilters()

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

	t.Info("Test complete")
}

func enrollmentName(e enrollmentStatus) string {
	if e == enrolled {
		return "enrolled"
	}
	return "unenrolled"
}

func locationName(l podLocation) string {
	if l == sameNode {
		return "same-node"
	}
	return "different-node"
}
