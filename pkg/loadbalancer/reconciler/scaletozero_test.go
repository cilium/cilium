// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/scaletozero/fake"
)

func TestReconcileScaleToZero(t *testing.T) {
	f := fake.NewFakeScaleToZeroMap()
	ops := &BPFOps{scaleToZero: f}

	name := loadbalancer.NewServiceName("ns", "svc")
	annotated := &loadbalancer.Service{
		Name:        name,
		Annotations: map[string]string{annotation.ServiceScaleToZero: "true"},
	}
	plain := &loadbalancer.Service{Name: loadbalancer.NewServiceName("ns", "plain")}

	// Annotated service is tracked under its k8s service name.
	require.NoError(t, ops.reconcileScaleToZero(1, annotated))
	assert.Equal(t, name, f.Entries[1])

	// Removing the annotation untracks it.
	require.NoError(t, ops.reconcileScaleToZero(1, plain))
	assert.NotContains(t, f.Entries, loadbalancer.ServiceID(1))

	// With the feature disabled (nil map) it is a no-op.
	require.NoError(t, (&BPFOps{}).reconcileScaleToZero(2, annotated))
}

func TestPruneScaleToZeroRemovesOrphans(t *testing.T) {
	f := &fake.ScaleToZeroMap{Entries: map[loadbalancer.ServiceID]loadbalancer.ServiceName{
		1: loadbalancer.NewServiceName("ns", "a"),
		2: loadbalancer.NewServiceName("ns", "orphan"),
		3: loadbalancer.NewServiceName("ns", "c"),
	}}
	ops := &BPFOps{scaleToZero: f}
	ops.serviceIDAlloc = newIDAllocator(firstFreeServiceID, maxSetOfServiceID)
	// Only ids 1 and 3 are still allocated; id 2 is an orphan.
	ops.serviceIDAlloc.idToAddr[1] = loadbalancer.L3n4Addr{}
	ops.serviceIDAlloc.idToAddr[3] = loadbalancer.L3n4Addr{}

	require.NoError(t, ops.pruneScaleToZero())
	assert.Contains(t, f.Entries, loadbalancer.ServiceID(1))
	assert.NotContains(t, f.Entries, loadbalancer.ServiceID(2), "orphan id must be pruned")
	assert.Contains(t, f.Entries, loadbalancer.ServiceID(3))

	// Feature disabled (nil map) is a no-op.
	require.NoError(t, (&BPFOps{}).pruneScaleToZero())
}
