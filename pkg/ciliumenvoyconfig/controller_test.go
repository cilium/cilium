// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func backend(addr string, port uint16, state loadbalancer.BackendState) *loadbalancer.Backend {
	return backendWith(addr, port, loadbalancer.TCP, state, []string{"http"})
}

func backendWith(addr string, port uint16, proto loadbalancer.L4Type, state loadbalancer.BackendState, portNames []string) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(
			proto,
			cmtypes.MustParseAddrCluster(addr),
			port,
			loadbalancer.ScopeExternal,
		),
		PortNames: portNames,
		State:     state,
	}
}

func healthByAddr(t *testing.T, assignments []*envoy_config_endpoint.ClusterLoadAssignment) map[string]envoy_config_core.HealthStatus {
	t.Helper()
	require.NotEmpty(t, assignments)
	require.NotEmpty(t, assignments[0].Endpoints)
	statusByAddr := map[string]envoy_config_core.HealthStatus{}
	for _, lep := range assignments[0].Endpoints[0].LbEndpoints {
		addr := lep.GetEndpoint().GetAddress().GetSocketAddress().GetAddress()
		statusByAddr[addr] = lep.GetHealthStatus()
	}
	return statusByAddr
}

func TestComputeLoadAssignmentsDraining(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "echo")
	clusterRefs := clusterReferences{
		{
			CECName:   CECName{Namespace: "test", Name: "envoy-lb-listener"},
			PortNames: sets.New("80"),
		},
	}
	portNames := map[string]uint16{"http": 80}

	t.Run("only active backends stay healthy", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateActive), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateActive), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Len(t, assignments, 1)
		require.Equal(t, "test/echo:80", assignments[0].ClusterName)

		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 2)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.2"])
	})

	t.Run("terminating backend marked DRAINING when active backends exist", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateActive), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Len(t, assignments, 1)

		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 2)
		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.2"])
	})

	t.Run("multiple terminating backends marked DRAINING when active backends exist", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.3", 8080, loadbalancer.BackendStateActive), 0)
			yield(backend("10.244.1.4", 8080, loadbalancer.BackendStateActive), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 4)
		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.2"])
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.3"])
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.4"])
	})

	t.Run("terminating backends used as fallback without DRAINING", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateTerminating), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Len(t, assignments, 1)

		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 2)
		for _, status := range statusByAddr {
			require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, status)
		}
	})

	t.Run("single terminating backend used as fallback without DRAINING", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 1)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
	})

	t.Run("quarantined and maintenance backends are skipped", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateActive), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateQuarantined), 0)
			yield(backend("10.244.1.3", 8080, loadbalancer.BackendStateMaintenance), 0)
			yield(backend("10.244.1.4", 8080, loadbalancer.BackendStateTerminatingNotServing), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 1)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
	})

	t.Run("quarantined backends do not count as active for DRAINING", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateQuarantined), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 1)
		// Quarantined is skipped, so terminating is a fallback (not DRAINING).
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
	})

	t.Run("mixed active terminating and quarantined", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateActive), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.3", 8080, loadbalancer.BackendStateQuarantined), 0)
			yield(backend("10.244.1.4", 8080, loadbalancer.BackendStateMaintenance), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 2)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.2"])
		_, hasQuarantined := statusByAddr["10.244.1.3"]
		_, hasMaintenance := statusByAddr["10.244.1.4"]
		require.False(t, hasQuarantined)
		require.False(t, hasMaintenance)
	})

	t.Run("empty backends produce no assignments", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Empty(t, assignments)
	})

	t.Run("UDP and SCTP backends are skipped", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backendWith("10.244.1.1", 8080, loadbalancer.TCP, loadbalancer.BackendStateActive, []string{"http"}), 0)
			yield(backendWith("10.244.1.2", 8080, loadbalancer.UDP, loadbalancer.BackendStateActive, []string{"http"}), 0)
			yield(backendWith("10.244.1.3", 8080, loadbalancer.SCTP, loadbalancer.BackendStateActive, []string{"http"}), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 1)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
	})

	t.Run("backends with unmatched port names are excluded", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backendWith("10.244.1.1", 8080, loadbalancer.TCP, loadbalancer.BackendStateActive, []string{"http"}), 0)
			yield(backendWith("10.244.1.2", 8080, loadbalancer.TCP, loadbalancer.BackendStateActive, []string{"grpc"}), 0)
			yield(backendWith("10.244.1.3", 8080, loadbalancer.TCP, loadbalancer.BackendStateTerminating, []string{"metrics"}), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 1)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
	})

	t.Run("backends match ports by service port number", func(t *testing.T) {
		refsByNumber := clusterReferences{
			{
				CECName:   CECName{Namespace: "test", Name: "envoy-lb-listener"},
				PortNames: sets.New("80"),
			},
		}
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			// Port name "http" maps to 80 in portNames, and refs filter by "80".
			yield(backendWith("10.244.1.1", 8080, loadbalancer.TCP, loadbalancer.BackendStateActive, []string{"http"}), 0)
			yield(backendWith("10.244.1.2", 8080, loadbalancer.TCP, loadbalancer.BackendStateTerminating, []string{"http"}), 0)
		}

		assignments := computeLoadAssignments(svcName, refsByNumber, portNames, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 2)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.2"])
	})

	t.Run("nameless backends match nameless service ports", func(t *testing.T) {
		refsByNumber := clusterReferences{
			{
				CECName:   CECName{Namespace: "test", Name: "envoy-lb-listener"},
				PortNames: sets.New("80"),
			},
		}
		namelessPorts := map[string]uint16{"": 80}
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backendWith("10.244.1.1", 8080, loadbalancer.TCP, loadbalancer.BackendStateActive, nil), 0)
			yield(backendWith("10.244.1.2", 8080, loadbalancer.TCP, loadbalancer.BackendStateTerminating, nil), 0)
		}

		assignments := computeLoadAssignments(svcName, refsByNumber, namelessPorts, backends)
		statusByAddr := healthByAddr(t, assignments)
		require.Len(t, statusByAddr, 2)
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.2"])
	})

	t.Run("any port publishes service-named assignment", func(t *testing.T) {
		anyPortRefs := clusterReferences{
			{
				CECName:   CECName{Namespace: "test", Name: "envoy-lb-listener"},
				PortNames: sets.New[string](),
			},
		}
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateActive), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateTerminating), 0)
		}

		assignments := computeLoadAssignments(svcName, anyPortRefs, portNames, backends)
		require.Len(t, assignments, 2)
		require.Equal(t, "test/echo:*", assignments[0].ClusterName)
		require.Equal(t, "test/echo", assignments[1].ClusterName)

		for _, assignment := range assignments {
			statusByAddr := map[string]envoy_config_core.HealthStatus{}
			for _, lep := range assignment.Endpoints[0].LbEndpoints {
				addr := lep.GetEndpoint().GetAddress().GetSocketAddress().GetAddress()
				statusByAddr[addr] = lep.GetHealthStatus()
			}
			require.Len(t, statusByAddr, 2)
			require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.1"])
			require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.2"])
		}
	})

	t.Run("endpoint address and port are preserved", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateActive), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Len(t, assignments, 1)
		lep := assignments[0].Endpoints[0].LbEndpoints[0]
		sock := lep.GetEndpoint().GetAddress().GetSocketAddress()
		require.Equal(t, "10.244.1.1", sock.GetAddress())
		require.Equal(t, uint32(8080), sock.GetPortValue())
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, lep.GetHealthStatus())
	})
}
