// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func backend(addr string, port uint16, state loadbalancer.BackendState) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			cmtypes.MustParseAddrCluster(addr),
			port,
			loadbalancer.ScopeExternal,
		),
		PortNames: []string{"http"},
		State:     state,
	}
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

	t.Run("terminating backend marked DRAINING when active backends exist", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateActive), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Len(t, assignments, 1)

		lbEndpoints := assignments[0].Endpoints[0].LbEndpoints
		require.Len(t, lbEndpoints, 2)

		statusByAddr := map[string]envoy_config_core.HealthStatus{}
		for _, lep := range lbEndpoints {
			addr := lep.GetEndpoint().GetAddress().GetSocketAddress().GetAddress()
			statusByAddr[addr] = lep.GetHealthStatus()
		}

		require.Equal(t, envoy_config_core.HealthStatus_DRAINING, statusByAddr["10.244.1.1"])
		require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, statusByAddr["10.244.1.2"])
	})

	t.Run("terminating backends used as fallback without DRAINING", func(t *testing.T) {
		backends := func(yield func(*loadbalancer.Backend, uint64) bool) {
			yield(backend("10.244.1.1", 8080, loadbalancer.BackendStateTerminating), 0)
			yield(backend("10.244.1.2", 8080, loadbalancer.BackendStateTerminating), 0)
		}

		assignments := computeLoadAssignments(svcName, clusterRefs, portNames, backends)
		require.Len(t, assignments, 1)

		for _, lep := range assignments[0].Endpoints[0].LbEndpoints {
			require.Equal(t, envoy_config_core.HealthStatus_UNKNOWN, lep.GetHealthStatus())
		}
	})
}
