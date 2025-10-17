// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func getCEP(name string, id int64) *capi_v2a1.CoreCiliumEndpoint {
	return &capi_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: id,
	}
}

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

func TestFCFSManagerDefault(t *testing.T) {
	log := hivetest.Logger(t)
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newCESManager(2, false, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newCESManager(2, false, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns")
		assert.Equal(t, 3, m.mapping.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newCESManager(5, false, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns1")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns2")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns3")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns4")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns5")
		assert.Equal(t, 5, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newCESManager(2, false, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c1", 5), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newCESManager(2, false, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns")
		m.RemoveCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns")
		m.RemoveCEPMapping(getCEP("c2", 0), "ns")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns")
		m.RemoveCEPMapping(getCEP("c3", 0), "ns")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 2, m.mapping.countCEPs(), "Total number of CEPs inserted is 2")
	})
}

func TestFCFSManager(t *testing.T) {
	log := hivetest.Logger(t)
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newCESManager(2, true, log)
		m.UpsertPodWithIdentity(getPod("p1", "ns"), "node1", getCID("1"))
		assert.Equal(t, 1, m.cache.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.cache.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newCESManager(2, true, log)
		m.UpsertPodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c2", "ns"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c3", "ns"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c4", "ns"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c5", "ns"), "node1", getCID("1"))
		assert.Equal(t, 3, m.cache.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.cache.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newCESManager(5, true, log)
		m.UpsertPodWithIdentity(getPod("c1", "ns1"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c2", "ns2"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c3", "ns3"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c4", "ns4"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c5", "ns5"), "node1", getCID("1"))
		assert.Equal(t, 5, m.cache.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.cache.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newCESManager(2, true, log)
		m.UpsertPodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		assert.Equal(t, 1, m.cache.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.cache.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newCESManager(2, true, log)
		m.UpsertPodWithIdentity(getPod("c1", "ns"), "node1", getCID("1"))
		m.UpsertPodWithIdentity(getPod("c2", "ns"), "node1", getCID("1"))
		m.RemovePodMapping(getPod("c1", "ns"))
		m.UpsertPodWithIdentity(getPod("c3", "ns"), "node1", getCID("1"))
		m.RemovePodMapping(getPod("c2", "ns"))
		m.UpsertPodWithIdentity(getPod("c4", "ns"), "node1", getCID("1"))
		m.RemovePodMapping(getPod("c3", "ns"))
		m.UpsertPodWithIdentity(getPod("c5", "ns"), "node1", getCID("1"))
		assert.Equal(t, 1, m.cache.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 2, m.cache.countCEPs(), "Total number of CEPs inserted is 2")
	})
}
