// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"iter"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// makeBackend creates a test backend. Pass forZones to simulate topology hints
// (trafficDistribution: PreferSameZone); omit them for a plain backend.
func makeBackend(ip string, port uint16, zone string, forZones ...string) *loadbalancer.Backend {
	be := &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			cmtypes.MustParseAddrCluster(ip),
			port,
			loadbalancer.ScopeExternal,
		),
		State: loadbalancer.BackendStateActive,
	}
	if zone != "" {
		be.Zone = &loadbalancer.BackendZone{Zone: zone, ForZones: forZones}
	}
	return be
}

func backendsSeq(bes []*loadbalancer.Backend) iter.Seq2[*loadbalancer.Backend, statedb.Revision] {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		for _, be := range bes {
			if !yield(be, 0) {
				return
			}
		}
	}
}

// allPorts returns a clusterReferences that matches all port names (anyPort).
func allPorts() clusterReferences {
	return clusterReferences{}
}

// --- Tests without topology hints (no ForZones): expect flat output ---

func TestComputeLoadAssignments_NoZone(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, ""),
		makeBackend("10.0.0.2", 8080, ""),
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1] // bare "test/backend" — what real CECs reference
	require.Len(t, cla.Endpoints, 1)
	require.Nil(t, cla.Endpoints[0].Locality, "expected no locality when zone is not set")
	require.Len(t, cla.Endpoints[0].LbEndpoints, 2)
}

// Zone is set on backends but no ForZones hints (service has no PreferSameZone)
// → flat output, no Locality grouping.
func TestComputeLoadAssignments_ZoneWithoutHints_SingleZone(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, "us-east-1a"),
		makeBackend("10.0.0.2", 8080, "us-east-1a"),
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1]
	require.Len(t, cla.Endpoints, 1)
	require.Nil(t, cla.Endpoints[0].Locality, "expected no locality without ForZones hints")
	require.Len(t, cla.Endpoints[0].LbEndpoints, 2)
}

// Multiple zones set but no ForZones hints → single flat group.
func TestComputeLoadAssignments_ZoneWithoutHints_MultiZone(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, "us-east-1a"),
		makeBackend("10.0.0.2", 8080, "us-east-1b"),
		makeBackend("10.0.0.3", 8080, "us-east-1a"),
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1]
	require.Len(t, cla.Endpoints, 1)
	require.Nil(t, cla.Endpoints[0].Locality, "expected no locality without ForZones hints")
	require.Len(t, cla.Endpoints[0].LbEndpoints, 3)
}

// Mixed: some backends have zone, some don't, none have ForZones → flat output.
func TestComputeLoadAssignments_ZoneWithoutHints_MixedZoneAndNoZone(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, "us-east-1a"),
		makeBackend("10.0.0.2", 8080, ""),
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1]
	require.Len(t, cla.Endpoints, 1)
	require.Nil(t, cla.Endpoints[0].Locality, "expected no locality without ForZones hints")
	require.Len(t, cla.Endpoints[0].LbEndpoints, 2)
}

// --- Tests with topology hints (ForZones set): expect zone-grouped output ---

// Single zone with hints → one LocalityLbEndpoints group with Locality set.
func TestComputeLoadAssignments_WithHints_SingleZone(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, "us-east-1a", "us-east-1a"),
		makeBackend("10.0.0.2", 8080, "us-east-1a", "us-east-1a"),
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1]
	require.Len(t, cla.Endpoints, 1)
	require.NotNil(t, cla.Endpoints[0].Locality)
	require.Equal(t, "us-east-1a", cla.Endpoints[0].Locality.Zone)
	require.Len(t, cla.Endpoints[0].LbEndpoints, 2)
	require.EqualValues(t, 2, cla.Endpoints[0].LoadBalancingWeight.GetValue())
}

// Multiple zones with hints → one group per zone, weight = endpoint count.
func TestComputeLoadAssignments_WithHints_MultiZone(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, "us-east-1a", "us-east-1a"),
		makeBackend("10.0.0.2", 8080, "us-east-1b", "us-east-1b"),
		makeBackend("10.0.0.3", 8080, "us-east-1a", "us-east-1a"),
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1]
	// Two zone groups sorted by name: us-east-1a (2 eps, weight=2), us-east-1b (1 ep, weight=1).
	require.Len(t, cla.Endpoints, 2)

	require.NotNil(t, cla.Endpoints[0].Locality)
	require.Equal(t, "us-east-1a", cla.Endpoints[0].Locality.Zone)
	require.Len(t, cla.Endpoints[0].LbEndpoints, 2)
	require.EqualValues(t, 2, cla.Endpoints[0].LoadBalancingWeight.GetValue())

	require.NotNil(t, cla.Endpoints[1].Locality)
	require.Equal(t, "us-east-1b", cla.Endpoints[1].Locality.Zone)
	require.Len(t, cla.Endpoints[1].LbEndpoints, 1)
	require.EqualValues(t, 1, cla.Endpoints[1].LoadBalancingWeight.GetValue())
}

// Mixed: some backends have hints, some don't → zoned group for hinted backends,
// flat group (nil Locality) for backends without hints.
func TestComputeLoadAssignments_WithHints_MixedHintedAndUnhinted(t *testing.T) {
	svcName := loadbalancer.NewServiceName("test", "backend")
	backends := []*loadbalancer.Backend{
		makeBackend("10.0.0.1", 8080, "us-east-1a", "us-east-1a"),
		makeBackend("10.0.0.2", 8080, "us-east-1b"), // zone set, no ForZones
	}

	assignments := computeLoadAssignments(svcName, allPorts(), nil, backendsSeq(backends))

	require.Len(t, assignments, 2)
	cla := assignments[1]
	// Two groups: "" (no hints, nil Locality) and "us-east-1a" (hinted).
	require.Len(t, cla.Endpoints, 2)

	// "" sorts before "us-east-1a".
	require.Nil(t, cla.Endpoints[0].Locality, "unhinted backend should have nil Locality")
	require.Len(t, cla.Endpoints[0].LbEndpoints, 1)
	require.EqualValues(t, 1, cla.Endpoints[0].LoadBalancingWeight.GetValue())

	require.NotNil(t, cla.Endpoints[1].Locality)
	require.Equal(t, "us-east-1a", cla.Endpoints[1].Locality.Zone)
	require.Len(t, cla.Endpoints[1].LbEndpoints, 1)
	require.EqualValues(t, 1, cla.Endpoints[1].LoadBalancingWeight.GetValue())
}
