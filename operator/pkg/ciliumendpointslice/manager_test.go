// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

func getCEP(name string, id int64) *capi_v2a1.CoreCiliumEndpoint {
	return &capi_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: id,
	}
}

func newNode(name string, key int) *capi_v2.CiliumNode {
	return &capi_v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: capi_v2.NodeSpec{
			Encryption: capi_v2.EncryptionSpec{
				Key: key,
			},
		},
	}
}

func TestFCFSManagerDefault(t *testing.T) {
	log := hivetest.Logger(t)
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newDefaultManager(2, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newDefaultManager(2, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns")
		assert.Equal(t, 3, m.mapping.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newDefaultManager(5, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns1")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns2")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns3")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns4")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns5")
		assert.Equal(t, 5, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newDefaultManager(2, log)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c1", 5), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newDefaultManager(2, log)
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

func TestSlimManagerNodes(t *testing.T) {
	log := hivetest.Logger(t)
	t.Run("Test adding new node, no encryption", func(*testing.T) {
		m := newSlimManager(2, log)
		m.UpdateNodeMapping(newNode("n1", 0), false, false)
		assert.Len(t, m.mapping.nodeData, 1, "Total number of nodes in cache is 1")
		key, _ := m.mapping.getEncryptionKey("n1")
		assert.EqualValues(t, 0, key, "Encryption key for node n1 is 0")
	})
	t.Run("Test adding new node, IPSec encryption", func(*testing.T) {
		m := newSlimManager(2, log)
		m.UpdateNodeMapping(newNode("n1", 5), true, false)
		assert.Len(t, m.mapping.nodeData, 1, "Total number of nodes in cache is 1")
		key, _ := m.mapping.getEncryptionKey("n1")
		assert.EqualValues(t, 5, key, "Encryption key for node n1 is 5")
	})
	t.Run("Test adding new node, Wireguard encryption", func(*testing.T) {
		m := newSlimManager(2, log)
		m.UpdateNodeMapping(newNode("n1", 5), false, true)
		assert.Len(t, m.mapping.nodeData, 1, "Total number of nodes in cache is 1")
		key, _ := m.mapping.getEncryptionKey("n1")
		assert.EqualValues(t, wgtypes.StaticEncryptKey, key, "Encryption key for node n1 is Wireguard StaticEncryptKey")
	})
	t.Run("Test adding and deleting nodes", func(*testing.T) {
		m := newSlimManager(2, log)
		m.UpdateNodeMapping(newNode("n1", 5), true, false)
		assert.Len(t, m.mapping.nodeData, 1, "Total number of nodes in cache is 1")
		m.UpdateNodeMapping(newNode("n2", 0), true, false)
		assert.Len(t, m.mapping.nodeData, 2, "Total number of nodes in cache is 2")
		m.RemoveNodeMapping(newNode("n1", 5))
		assert.Len(t, m.mapping.nodeData, 1, "Total number of nodes in cache is 1")
		m.RemoveNodeMapping(newNode("n2", 0))
		assert.Empty(t, m.mapping.nodeData, "Total number of nodes in cache is 0")
	})
}
