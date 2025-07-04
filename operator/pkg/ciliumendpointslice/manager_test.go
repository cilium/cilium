// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func getPod(name string, ns string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}
}

func getCID(name string) *cilium_v2.CiliumIdentity {
	return &cilium_v2.CiliumIdentity{
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
	}
}

func TestFCFSManager(t *testing.T) {
	log := hivetest.Logger(t)
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newCESManager(2, log)
		m.UpdatePodWithIdentity(getPod("p1", "ns"), "node1", getCID("1"))
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newCESManager(2, log)
		m.UpdatePodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c2", "ns"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c3", "ns"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c4", "ns"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c5", "ns"), "node1", getCID("1"))
		assert.Equal(t, 3, m.mapping.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newCESManager(5, log)
		m.UpdatePodWithIdentity(getPod("c1", "ns1"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c2", "ns2"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c3", "ns3"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c4", "ns4"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c5", "ns5"), "node1", getCID("1"))
		assert.Equal(t, 5, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newCESManager(2, log)
		m.UpdatePodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newCESManager(2, log)
		m.UpdatePodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		m.UpdatePodWithIdentity(getPod("c2", "ns"), "node1", getCID("1"))
		m.RemovePodMapping(getPod("c1", "ns"))
		m.UpdatePodWithIdentity(getPod("c3", "ns"), "node1", getCID("1"))
		m.RemovePodMapping(getPod("c2", "ns"))
		m.UpdatePodWithIdentity(getPod("c4", "ns"), "node1", getCID("1"))
		m.RemovePodMapping(getPod("c3", "ns"))
		m.UpdatePodWithIdentity(getPod("c5", "ns"), "node1", getCID("1"))
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 2, m.mapping.countCEPs(), "Total number of CEPs inserted is 2")
	})
}
