// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/annotation"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func newFakeConnectivityTest(t *testing.T, objects ...runtime.Object) (*ConnectivityTest, *k8s.Client) {
	t.Helper()

	client := &k8s.Client{
		Clientset: fake.NewSimpleClientset(objects...),
	}

	ct := &ConnectivityTest{
		params: Parameters{
			TestNamespace:        "default-test-namespace",
			Writer:               &bytes.Buffer{},
			NamespaceLabels:      map[string]string{"suite": "connectivity"},
			NamespaceAnnotations: map[string]string{"owner": "test"},
			CurlImage:            "quay.io/cilium/alpine-curl:latest",
			IPFamilies:           []string{features.IPFamilyV4.String(), features.IPFamilyV6.String()},
		},
		Features: features.Set{
			features.DefaultGlobalNamespace: {Enabled: false},
		},
		client: client,
		clients: &deploymentClients{
			src: client,
			dst: client,
		},
		echoPods: make(map[string]Pod),
	}

	return ct, client
}

func echoPod(name string, phase corev1.PodPhase, reason string, ips ...string) *corev1.Pod {
	podIPs := make([]corev1.PodIP, 0, len(ips))
	for _, ip := range ips {
		podIPs = append(podIPs, corev1.PodIP{IP: ip})
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default-test-namespace",
			Labels:    map[string]string{"kind": kindEchoName},
		},
		Status: corev1.PodStatus{Phase: phase, Reason: reason, PodIPs: podIPs},
	}
}

func TestRegisterEchoPodsSkipsSupersededLeftovers(t *testing.T) {
	ct, _ := newFakeConnectivityTest(t,
		echoPod("echo-other-node-live", corev1.PodRunning, "", "10.0.0.1"),
		echoPod("echo-other-node-evicted", corev1.PodFailed, "Evicted"),
	)

	require.NoError(t, ct.registerEchoPods(context.Background()))
	require.Len(t, ct.EchoPods(), 1)
	assert.Contains(t, ct.EchoPods(), "echo-other-node-live")
}

func TestDeployNamespaceCreatesMissingNamespace(t *testing.T) {
	ct, client := newFakeConnectivityTest(t)

	err := ct.deployNamespace(context.Background(), client, "created-ns")
	require.NoError(t, err)

	namespace, err := client.GetNamespace(context.Background(), "created-ns", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "created-ns", namespace.Name)
	assert.Equal(t, "connectivity", namespace.Labels["suite"])
	assert.Equal(t, "cilium-cli", namespace.Labels["app.kubernetes.io/name"])
	assert.Equal(t, "test", namespace.Annotations["owner"])
	assert.Equal(t, "true", namespace.Annotations[annotation.GlobalNamespace])
}

func TestDeployNamespaceUpdatesExistingNamespace(t *testing.T) {
	existing := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "existing-ns",
			Annotations: map[string]string{"existing": "annotation"},
			Labels:      map[string]string{"existing": "label"},
		},
	}
	ct, client := newFakeConnectivityTest(t, existing)

	err := ct.deployNamespace(context.Background(), client, "existing-ns")
	require.NoError(t, err)

	namespace, err := client.GetNamespace(context.Background(), "existing-ns", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "annotation", namespace.Annotations["existing"])
	assert.Equal(t, "true", namespace.Annotations[annotation.GlobalNamespace])
	assert.Equal(t, "label", namespace.Labels["existing"])
}

func TestDeployNamespaceUsesProvidedNamespaceName(t *testing.T) {
	ct, client := newFakeConnectivityTest(t)
	ct.params.TestNamespace = "wrong-ns"

	err := ct.deployNamespace(context.Background(), client, "actual-ns")
	require.NoError(t, err)

	_, err = client.GetNamespace(context.Background(), "actual-ns", metav1.GetOptions{})
	require.NoError(t, err)

	_, err = client.GetNamespace(context.Background(), "wrong-ns", metav1.GetOptions{})
	assert.Error(t, err)
}

func TestDeployCCNPTestEnvCreatesNamespacesAndDeployments(t *testing.T) {
	ct, client := newFakeConnectivityTest(t)

	err := ct.deployCCNPTestEnv(context.Background())
	require.NoError(t, err)

	for _, namespaceName := range []string{ccnpTestNamespace1, ccnpTestNamespace2} {
		namespace, err := client.GetNamespace(context.Background(), namespaceName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, "true", namespace.Annotations[annotation.GlobalNamespace])

		serviceAccount, err := client.GetServiceAccount(context.Background(), namespaceName, ccnpDeploymentName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, ccnpDeploymentName, serviceAccount.Name)

		deployment, err := client.GetDeployment(context.Background(), namespaceName, ccnpDeploymentName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, ccnpDeploymentName, deployment.Name)
		assert.Equal(t, kindCCNPName, deployment.Labels["kind"])
	}
}

func TestGetServiceClusterIP(t *testing.T) {
	tests := []struct {
		name     string
		service  *corev1.Service
		family   features.IPFamily
		expected string
	}{
		{
			name: "ipv4 service requests ipv4",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					ClusterIPs: []string{"10.96.0.1"},
					ClusterIP:  "10.96.0.1",
				},
			},
			family:   features.IPFamilyV4,
			expected: "10.96.0.1",
		},
		{
			name: "ipv4 service requests ipv6",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					ClusterIPs: []string{"10.96.0.1"},
					ClusterIP:  "10.96.0.1",
				},
			},
			family:   features.IPFamilyV6,
			expected: "",
		},
		{
			name: "dual-stack service ipv4 first requests ipv4",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
					ClusterIPs: []string{"10.96.0.1", "fd00::1"},
					ClusterIP:  "10.96.0.1",
				},
			},
			family:   features.IPFamilyV4,
			expected: "10.96.0.1",
		},
		{
			name: "dual-stack service ipv4 first requests ipv6",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
					ClusterIPs: []string{"10.96.0.1", "fd00::1"},
					ClusterIP:  "10.96.0.1",
				},
			},
			family:   features.IPFamilyV6,
			expected: "fd00::1",
		},
		{
			name: "dual-stack service ipv6 first requests ipv4",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol, corev1.IPv4Protocol},
					ClusterIPs: []string{"fd00::1", "10.96.0.1"},
					ClusterIP:  "fd00::1",
				},
			},
			family:   features.IPFamilyV4,
			expected: "10.96.0.1",
		},
		{
			name: "dual-stack service ipv6 first requests ipv6",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol, corev1.IPv4Protocol},
					ClusterIPs: []string{"fd00::1", "10.96.0.1"},
					ClusterIP:  "fd00::1",
				},
			},
			family:   features.IPFamilyV6,
			expected: "fd00::1",
		},
		{
			name: "legacy single stack fallback v4",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: "10.96.0.1",
				},
			},
			family:   features.IPFamilyV4,
			expected: "10.96.0.1",
		},
		{
			name: "legacy single stack fallback v6",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: "fd00::1",
				},
			},
			family:   features.IPFamilyV6,
			expected: "fd00::1",
		},
		{
			name: "headless service",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: corev1.ClusterIPNone,
				},
			},
			family:   features.IPFamilyV4,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := getServiceClusterIP(tt.service, tt.family)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestNewConnDisruptCEGP(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		features      features.Set
		expectedCIDRs []string
	}{
		{
			name:    "ipv4 only",
			version: "1.18.0",
			features: features.Set{
				features.IPv4: {Enabled: true},
				features.IPv6: {Enabled: false},
			},
			expectedCIDRs: []string{"0.0.0.0/0"},
		},
		{
			name:    "dual stack cilium >= 1.18.0",
			version: "1.18.0",
			features: features.Set{
				features.IPv4: {Enabled: true},
				features.IPv6: {Enabled: true},
			},
			expectedCIDRs: []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:    "dual stack cilium < 1.18.0",
			version: "1.17.0",
			features: features.Set{
				features.IPv4: {Enabled: true},
				features.IPv6: {Enabled: true},
			},
			expectedCIDRs: []string{"0.0.0.0/0"},
		},
		{
			name:    "ipv6 only cilium >= 1.18.0",
			version: "1.18.0",
			features: features.Set{
				features.IPv4: {Enabled: false},
				features.IPv6: {Enabled: true},
			},
			expectedCIDRs: []string{"::/0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, _ := newFakeConnectivityTest(t)
			ct.CiliumVersion = semver.MustParse(tt.version)
			ct.Features = tt.features

			cegp := ct.newConnDisruptCEGP("gw-node-1")
			require.NotNil(t, cegp)
			assert.Equal(t, testConnDisruptCEGPName, cegp.Name)
			assert.Equal(t, "gw-node-1", string(cegp.Spec.EgressGateway.NodeSelector.MatchLabels["kubernetes.io/hostname"]))

			var cidrStrs []string
			for _, cidr := range cegp.Spec.DestinationCIDRs {
				cidrStrs = append(cidrStrs, cidr.String())
			}
			assert.Equal(t, tt.expectedCIDRs, cidrStrs)
		})
	}
}

func TestGetConnDisruptEgressPolicyEntries(t *testing.T) {
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-conn-disrupt-client-egw-gw-node-ipv4-1",
			Namespace: "default-test-namespace",
			Labels: map[string]string{
				"kind": KindTestConnDisruptEgressGateway,
				"app":  "test-conn-disrupt-client-egw-gw-node-ipv4",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.5",
			PodIPs: []corev1.PodIP{
				{IP: "10.244.1.5"},
				{IP: "fd00:1::5"},
			},
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-conn-disrupt-client-egw-non-gw-node-ipv4-1",
			Namespace: "default-test-namespace",
			Labels: map[string]string{
				"kind": KindTestConnDisruptEgressGateway,
				"app":  "test-conn-disrupt-client-egw-non-gw-node-ipv4",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node2",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.2.5",
			PodIPs: []corev1.PodIP{
				{IP: "10.244.2.5"},
				{IP: "fd00:2::5"},
			},
		},
	}

	// Server pod should be skipped
	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-conn-disrupt-server-egw-1",
			Namespace: "default-test-namespace",
			Labels: map[string]string{
				"kind": KindTestConnDisruptEgressGateway,
				"app":  testConnDisruptServerEgressGatewayAppLabel,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.99",
		},
	}

	setupCT := func(ipv6Enabled bool, ciliumVersion string) *ConnectivityTest {
		ct, _ := newFakeConnectivityTest(t, pod1, pod2, serverPod)
		ct.CiliumVersion = semver.MustParse(ciliumVersion)
		ct.Features = features.Set{
			features.IPv4: {Enabled: true},
			features.IPv6: {Enabled: ipv6Enabled},
		}
		ct.nodes = map[string]*slimcorev1.Node{
			"node1": {
				ObjectMeta: slimmetav1.ObjectMeta{Name: "node1"},
				Status: slimcorev1.NodeStatus{
					Addresses: []slimcorev1.NodeAddress{
						{Type: slimcorev1.NodeInternalIP, Address: "192.168.1.10"},
						{Type: slimcorev1.NodeInternalIP, Address: "2001:db8::10"},
					},
				},
			},
			"node2": {
				ObjectMeta: slimmetav1.ObjectMeta{Name: "node2"},
				Status: slimcorev1.NodeStatus{
					Addresses: []slimcorev1.NodeAddress{
						{Type: slimcorev1.NodeInternalIP, Address: "192.168.1.11"},
						{Type: slimcorev1.NodeInternalIP, Address: "2001:db8::11"},
					},
				},
			},
		}
		ct.controlPlaneNodes = map[string]*slimcorev1.Node{}
		return ct
	}

	t.Run("dual stack on gateway node cilium >= 1.18.0", func(t *testing.T) {
		ct := setupCT(true, "1.18.0")
		ciliumPod := Pod{
			Pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}

		entries, err := ct.GetConnDisruptEgressPolicyEntries(context.Background(), ciliumPod)
		require.NoError(t, err)
		require.Len(t, entries, 4)

		expected := []BPFEgressGatewayPolicyEntry{
			{SourceIP: "10.244.1.5", DestCIDR: "0.0.0.0/0", EgressIP: "192.168.1.10", GatewayIP: "192.168.1.10"},
			{SourceIP: "fd00:1::5", DestCIDR: "::/0", EgressIP: "2001:db8::10", GatewayIP: "192.168.1.10"},
			{SourceIP: "10.244.2.5", DestCIDR: "0.0.0.0/0", EgressIP: "192.168.1.10", GatewayIP: "192.168.1.10"},
			{SourceIP: "fd00:2::5", DestCIDR: "::/0", EgressIP: "2001:db8::10", GatewayIP: "192.168.1.10"},
		}
		assert.ElementsMatch(t, expected, entries)
	})

	t.Run("dual stack on non-gateway node cilium >= 1.18.0", func(t *testing.T) {
		ct := setupCT(true, "1.18.0")
		ciliumPod := Pod{
			Pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					NodeName: "node2",
				},
			},
		}

		entries, err := ct.GetConnDisruptEgressPolicyEntries(context.Background(), ciliumPod)
		require.NoError(t, err)
		require.Len(t, entries, 4)

		expected := []BPFEgressGatewayPolicyEntry{
			{SourceIP: "10.244.1.5", DestCIDR: "0.0.0.0/0", EgressIP: "0.0.0.0", GatewayIP: "192.168.1.10"},
			{SourceIP: "fd00:1::5", DestCIDR: "::/0", EgressIP: "::", GatewayIP: "192.168.1.10"},
			{SourceIP: "10.244.2.5", DestCIDR: "0.0.0.0/0", EgressIP: "0.0.0.0", GatewayIP: "192.168.1.10"},
			{SourceIP: "fd00:2::5", DestCIDR: "::/0", EgressIP: "::", GatewayIP: "192.168.1.10"},
		}
		assert.ElementsMatch(t, expected, entries)
	})

	t.Run("ipv4 only cluster", func(t *testing.T) {
		ct := setupCT(false, "1.18.0")
		ciliumPod := Pod{
			Pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}

		entries, err := ct.GetConnDisruptEgressPolicyEntries(context.Background(), ciliumPod)
		require.NoError(t, err)
		require.Len(t, entries, 2)

		expected := []BPFEgressGatewayPolicyEntry{
			{SourceIP: "10.244.1.5", DestCIDR: "0.0.0.0/0", EgressIP: "192.168.1.10", GatewayIP: "192.168.1.10"},
			{SourceIP: "10.244.2.5", DestCIDR: "0.0.0.0/0", EgressIP: "192.168.1.10", GatewayIP: "192.168.1.10"},
		}
		assert.ElementsMatch(t, expected, entries)
	})
}

