// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func getPod(name string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: name,
		},
	}
}

func TestFCFSManager(t *testing.T) {
	log := hivetest.Logger(t)
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newCESManager(2, log).(*cesManager)
		m.UpdatePodMapping(getPod("p1"), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newCESManager(2, log).(*cesManager)
		m.UpdatePodMapping(getPod("c1"), "ns")
		m.UpdatePodMapping(getPod("c2"), "ns")
		m.UpdatePodMapping(getPod("c3"), "ns")
		m.UpdatePodMapping(getPod("c4"), "ns")
		m.UpdatePodMapping(getPod("c5"), "ns")
		assert.Equal(t, 3, m.mapping.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newCESManager(5, log).(*cesManager)
		m.UpdatePodMapping(getPod("c1"), "ns1")
		m.UpdatePodMapping(getPod("c2"), "ns2")
		m.UpdatePodMapping(getPod("c3"), "ns3")
		m.UpdatePodMapping(getPod("c4"), "ns4")
		m.UpdatePodMapping(getPod("c5"), "ns5")
		assert.Equal(t, 5, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newCESManager(2, log).(*cesManager)
		m.UpdatePodMapping(getPod("c1"), "ns")
		m.UpdatePodMapping(getPod("c1"), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newCESManager(2, log).(*cesManager)
		m.UpdatePodMapping(getPod("c1"), "ns")
		m.UpdatePodMapping(getPod("c2"), "ns")
		m.RemovePodMapping(getPod("c1"), "ns")
		m.UpdatePodMapping(getPod("c3"), "ns")
		m.RemovePodMapping(getPod("c2"), "ns")
		m.UpdatePodMapping(getPod("c4"), "ns")
		m.RemovePodMapping(getPod("c3"), "ns")
		m.UpdatePodMapping(getPod("c5"), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 2, m.mapping.countCEPs(), "Total number of CEPs inserted is 2")
	})
}
