// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/workloadapi"

	"github.com/cilium/cilium/pkg/endpoint"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func TestEndpointEventToXDSAddress(t *testing.T) {
	t.Run("CREATE Event", func(t *testing.T) {
		// Create endpoint with both IPv4 and IPv6
		ep := &endpoint.Endpoint{
			ID:           1001,
			K8sUID:       "test-uid-12345678-1234-1234-1234-123456789abc",
			K8sPodName:   "test-pod",
			K8sNamespace: "test-namespace",
			IPv4:         netip.MustParseAddr("10.0.1.10"),
			IPv6:         netip.MustParseAddr("fd00::1:100"),
		}

		// Create Pod with required spec fields
		pod := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "test-node",
				ServiceAccountName: "test-service-account",
			},
		}
		ep.SetPod(pod)

		// Create EndpointEvent for CREATE
		event := &EndpointEvent{
			Type:     CREATE,
			Endpoint: ep,
		}

		// Transform to XDS Address
		address, err := event.ToXDSAddress()
		require.NoError(t, err, "ToXDSAddress should not error for valid endpoint")
		require.NotNil(t, address, "Address should not be nil")

		// Validate Address structure
		workload := address.GetWorkload()
		require.NotNil(t, workload, "Address should contain Workload")

		// Validate all required field mappings from endpoint to workload
		require.Equal(t, ep.K8sUID, workload.Uid, "Workload.Uid should match endpoint.K8sUID")
		require.Equal(t, ep.K8sPodName, workload.Name, "Workload.Name should match endpoint.K8sPodName")
		require.Equal(t, ep.K8sNamespace, workload.Namespace, "Workload.Namespace should match endpoint.K8sNamespace")
		require.Equal(t, pod.Spec.NodeName, workload.Node, "Workload.Node should match pod.Spec.NodeName")
		require.Equal(t, pod.Spec.ServiceAccountName, workload.ServiceAccount, "Workload.ServiceAccount should match pod.Spec.ServiceAccountName")
		require.Equal(t, workloadapi.TunnelProtocol_HBONE, workload.TunnelProtocol, "Workload.TunnelProtocol should be HBONE")

		// Validate IP addresses (dual-stack should have 2 addresses)
		require.Len(t, workload.Addresses, 2, "Should have 2 IP addresses for dual-stack endpoint")

		// Validate IPv4 address bytes
		ipv4Bytes := ep.IPv4.AsSlice()
		require.Contains(t, workload.Addresses, ipv4Bytes, "IPv4 address should be present in workload addresses")

		// Validate IPv6 address bytes
		ipv6Bytes := ep.IPv6.AsSlice()
		require.Contains(t, workload.Addresses, ipv6Bytes, "IPv6 address should be present in workload addresses")
	})

	t.Run("REMOVE Event", func(t *testing.T) {
		// Create endpoint with both IPv4 and IPv6 for REMOVE event
		ep := &endpoint.Endpoint{
			ID:           2001,
			K8sUID:       "remove-uid-87654321-4321-4321-4321-cba987654321",
			K8sPodName:   "remove-pod",
			K8sNamespace: "remove-namespace",
			IPv4:         netip.MustParseAddr("192.168.1.50"),
			IPv6:         netip.MustParseAddr("2001:db8::42"),
		}

		// Create Pod with required spec fields
		pod := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "remove-node",
				ServiceAccountName: "remove-service-account",
			},
		}
		ep.SetPod(pod)

		// Create EndpointEvent for REMOVE
		event := &EndpointEvent{
			Type:     REMOVED,
			Endpoint: ep,
		}

		// Transform to XDS Address
		// Note: REMOVE events don't use ToXDSAddress() in the transformation pipeline.
		// They are handled directly by adding the K8sUID to RemovedResources in
		// ToDeltaDiscoveryResponse(). However, the method should still work.
		address, err := event.ToXDSAddress()
		require.NoError(t, err, "ToXDSAddress should not error for REMOVE event")
		require.NotNil(t, address, "Address should not be nil")

		// Validate Address structure (same as CREATE)
		workload := address.GetWorkload()
		require.NotNil(t, workload, "Address should contain Workload")

		// Validate all required field mappings from endpoint to workload
		require.Equal(t, ep.K8sUID, workload.Uid, "Workload.Uid should match endpoint.K8sUID")
		require.Equal(t, ep.K8sPodName, workload.Name, "Workload.Name should match endpoint.K8sPodName")
		require.Equal(t, ep.K8sNamespace, workload.Namespace, "Workload.Namespace should match endpoint.K8sNamespace")
		require.Equal(t, pod.Spec.NodeName, workload.Node, "Workload.Node should match pod.Spec.NodeName")
		require.Equal(t, pod.Spec.ServiceAccountName, workload.ServiceAccount, "Workload.ServiceAccount should match pod.Spec.ServiceAccountName")
		require.Equal(t, workloadapi.TunnelProtocol_HBONE, workload.TunnelProtocol, "Workload.TunnelProtocol should be HBONE")

		// Validate IP addresses (dual-stack should have 2 addresses)
		require.Len(t, workload.Addresses, 2, "Should have 2 IP addresses for dual-stack endpoint")

		// Validate IPv4 address bytes
		ipv4Bytes := ep.IPv4.AsSlice()
		require.Contains(t, workload.Addresses, ipv4Bytes, "IPv4 address should be present in workload addresses")

		// Validate IPv6 address bytes
		ipv6Bytes := ep.IPv6.AsSlice()
		require.Contains(t, workload.Addresses, ipv6Bytes, "IPv6 address should be present in workload addresses")
	})

	t.Run("Missing Pod Information", func(t *testing.T) {
		// Create endpoint without pod information to test error case
		ep := &endpoint.Endpoint{
			ID:           1004,
			K8sUID:       "no-pod-uid-12345678-1234-1234-1234-123456789abc",
			K8sPodName:   "no-pod",
			K8sNamespace: "no-pod-namespace",
			IPv4:         netip.MustParseAddr("10.0.1.20"),
			IPv6:         netip.MustParseAddr("fd00::1:200"),
		}
		// Don't call ep.SetPod() - leave pod as nil

		event := &EndpointEvent{
			Type:     CREATE,
			Endpoint: ep,
		}

		// Should return error for missing pod information
		address, err := event.ToXDSAddress()
		require.Error(t, err, "ToXDSAddress should error when pod is nil")
		require.Nil(t, address, "Address should be nil when error occurs")
		require.Contains(t, err.Error(), "missing Pod information", "Error should mention missing Pod information")
	})
}

func TestEndpointEventCollectionToDeltaDiscoveryResponse(t *testing.T) {
	t.Run("CREATE-REMOVE-CREATE Collection", func(t *testing.T) {
		// Create UIDs for the three events
		testUIDs := []string{
			"create1-uid-12345678-1234-1234-1234-123456789abc",
			"remove-uid-87654321-4321-4321-4321-cba987654321",
			"create2-uid-abcdef12-5678-9012-3456-789012345678",
		}

		// CREATE Endpoint 1
		createEp1 := &endpoint.Endpoint{
			ID:           3001,
			K8sUID:       testUIDs[0],
			K8sPodName:   "create-pod-1",
			K8sNamespace: "create-namespace-1",
			IPv4:         netip.MustParseAddr("10.1.1.10"),
			IPv6:         netip.MustParseAddr("fd00::1:100"),
		}
		createPod1 := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "create-node-1",
				ServiceAccountName: "create-sa-1",
			},
		}
		createEp1.SetPod(createPod1)

		// REMOVE Endpoint
		removeEp := &endpoint.Endpoint{
			ID:           3002,
			K8sUID:       testUIDs[1],
			K8sPodName:   "remove-pod",
			K8sNamespace: "remove-namespace",
			IPv4:         netip.MustParseAddr("10.2.2.20"),
			IPv6:         netip.MustParseAddr("fd00::2:200"),
		}
		removePod := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "remove-node",
				ServiceAccountName: "remove-sa",
			},
		}
		removeEp.SetPod(removePod)

		// CREATE Endpoint 2
		createEp2 := &endpoint.Endpoint{
			ID:           3003,
			K8sUID:       testUIDs[2],
			K8sPodName:   "create-pod-2",
			K8sNamespace: "create-namespace-2",
			IPv4:         netip.MustParseAddr("10.3.3.30"),
			IPv6:         netip.MustParseAddr("fd00::3:300"),
		}
		createPod2 := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "create-node-2",
				ServiceAccountName: "create-sa-2",
			},
		}
		createEp2.SetPod(createPod2)

		// Create EndpointEventCollection with CREATE, REMOVE, CREATE sequence
		collection := EndpointEventCollection{
			&EndpointEvent{Type: CREATE, Endpoint: createEp1},
			&EndpointEvent{Type: REMOVED, Endpoint: removeEp},
			&EndpointEvent{Type: CREATE, Endpoint: createEp2},
		}

		// Transform to DeltaDiscoveryResponse
		response := collection.ToDeltaDiscoveryResponse()
		require.NotNil(t, response, "DeltaDiscoveryResponse should not be nil")

		// Validate response structure
		require.Equal(t, xdsTypeURLAddress, response.TypeUrl, "TypeUrl should be xdsTypeURLAddress")
		require.NotEmpty(t, response.Nonce, "Nonce should not be empty")

		// Validate CREATE resources (should be 2: createEp1 and createEp2)
		require.Len(t, response.Resources, 2, "Should have 2 CREATE resources")
		expectedCreateUIDs := []string{testUIDs[0], testUIDs[2]}
		actualCreateUIDs := make([]string, len(response.Resources))
		for i, resource := range response.Resources {
			actualCreateUIDs[i] = resource.Name
			require.NotNil(t, resource.Resource, "Resource should contain workload data")

			// Validate resource can be unmarshaled to workloadapi.Address
			var addr workloadapi.Address
			err := resource.Resource.UnmarshalTo(&addr)
			require.NoError(t, err, "Should be able to unmarshal workload address")

			workload := addr.GetWorkload()
			require.NotNil(t, workload, "Address should contain workload")

			// Validate workload fields based on UID
			switch resource.Name {
			case testUIDs[0]: // createEp1
				require.Equal(t, testUIDs[0], workload.Uid)
				require.Equal(t, "create-pod-1", workload.Name)
				require.Equal(t, "create-namespace-1", workload.Namespace)
				require.Equal(t, "create-node-1", workload.Node)
				require.Equal(t, "create-sa-1", workload.ServiceAccount)
				require.Equal(t, workloadapi.TunnelProtocol_HBONE, workload.TunnelProtocol)
				require.Len(t, workload.Addresses, 2, "Should have 2 IP addresses")

			case testUIDs[2]: // createEp2
				require.Equal(t, testUIDs[2], workload.Uid)
				require.Equal(t, "create-pod-2", workload.Name)
				require.Equal(t, "create-namespace-2", workload.Namespace)
				require.Equal(t, "create-node-2", workload.Node)
				require.Equal(t, "create-sa-2", workload.ServiceAccount)
				require.Equal(t, workloadapi.TunnelProtocol_HBONE, workload.TunnelProtocol)
				require.Len(t, workload.Addresses, 2, "Should have 2 IP addresses")

			default:
				t.Fatalf("Unexpected resource UID: %s", resource.Name)
			}
		}
		require.ElementsMatch(t, expectedCreateUIDs, actualCreateUIDs, "CREATE resource UIDs should match expected")

		// Validate REMOVE resources (should be 1: removeEp)
		require.Len(t, response.RemovedResources, 1, "Should have 1 REMOVE resource")
		require.Equal(t, testUIDs[1], response.RemovedResources[0], "REMOVE resource UID should match removeEp UID")
	})

	t.Run("Invalid Endpoint", func(t *testing.T) {
		// Create endpoint without pod to test error handling
		invalidEp := &endpoint.Endpoint{
			ID:           4001,
			K8sUID:       "invalid-uid-12345678-1234-1234-1234-123456789abc",
			K8sPodName:   "invalid-pod",
			K8sNamespace: "invalid-namespace",
			IPv4:         netip.MustParseAddr("10.4.4.40"),
		}
		// Don't set pod - this will cause ToXDSAddress to fail

		validEp := &endpoint.Endpoint{
			ID:           4002,
			K8sUID:       "valid-uid-87654321-4321-4321-4321-cba987654321",
			K8sPodName:   "valid-pod",
			K8sNamespace: "valid-namespace",
			IPv4:         netip.MustParseAddr("10.5.5.50"),
			IPv6:         netip.MustParseAddr("fd00::5:500"),
		}
		validPod := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "valid-node",
				ServiceAccountName: "valid-sa",
			},
		}
		validEp.SetPod(validPod)

		// Create collection with invalid CREATE and valid CREATE
		collection := EndpointEventCollection{
			&EndpointEvent{Type: CREATE, Endpoint: invalidEp}, // Will fail transformation
			&EndpointEvent{Type: CREATE, Endpoint: validEp},   // Will succeed
		}

		// Transform to DeltaDiscoveryResponse
		response := collection.ToDeltaDiscoveryResponse()
		require.NotNil(t, response, "DeltaDiscoveryResponse should not be nil")

		// Should only contain the valid endpoint (invalid one is skipped)
		require.Len(t, response.Resources, 1, "Should have 1 valid CREATE resource")
		require.Equal(t, "valid-uid-87654321-4321-4321-4321-cba987654321", response.Resources[0].Name, "Should contain only the valid endpoint")
		require.Empty(t, response.RemovedResources, "Should have no REMOVE resources")
	})
}
