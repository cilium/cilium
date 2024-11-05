// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"

	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func getCEP(name string, id int64) *capi_v2a1.CoreCiliumEndpoint {
	return &capi_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: id,
	}
}

func TestFCFSManager(t *testing.T) {
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns")
		assert.Equal(t, 3, m.mapping.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newCESManagerFcfs(5, log).(*cesManagerFcfs)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns1")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns2")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns3")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns4")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns5")
		assert.Equal(t, 5, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c1", 5), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
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

func TestIdentityManager(t *testing.T) {
	t.Run("Test adding new CEP to map", func(*testing.T) {
		m := newCESManagerIdentity(2, log).(*cesManagerIdentity)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test creating enough CESs", func(*testing.T) {
		m := newCESManagerIdentity(2, log).(*cesManagerIdentity)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns")
		assert.Equal(t, 3, m.mapping.getCESCount(), "Total number of CESs allocated is 3")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the CEPs from different namespaces in different CESs", func(*testing.T) {
		m := newCESManagerIdentity(5, log).(*cesManagerIdentity)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns1")
		m.UpdateCEPMapping(getCEP("c2", 0), "ns2")
		m.UpdateCEPMapping(getCEP("c3", 0), "ns3")
		m.UpdateCEPMapping(getCEP("c4", 0), "ns4")
		m.UpdateCEPMapping(getCEP("c5", 0), "ns5")
		assert.Equal(t, 5, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test grouping by id", func(*testing.T) {
		m := newCESManagerIdentity(2, log).(*cesManagerIdentity)
		m.UpdateCEPMapping(getCEP("c1", 1), "ns")
		m.UpdateCEPMapping(getCEP("c2", 2), "ns")
		m.UpdateCEPMapping(getCEP("c3", 3), "ns")
		m.UpdateCEPMapping(getCEP("c4", 4), "ns")
		m.UpdateCEPMapping(getCEP("c5", 4), "ns")
		assert.Equal(t, 4, m.mapping.getCESCount(), "Total number of CESs allocated is 4")
		assert.Equal(t, 5, m.mapping.countCEPs(), "Total number of CEPs inserted is 5")
	})
	t.Run("Test keeping the same mapping", func(*testing.T) {
		m := newCESManagerIdentity(2, log).(*cesManagerIdentity)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test moving CEP when ID changed", func(*testing.T) {
		m := newCESManagerIdentity(2, log).(*cesManagerIdentity)
		m.UpdateCEPMapping(getCEP("c1", 0), "ns")
		m.UpdateCEPMapping(getCEP("c1", 1), "ns")
		assert.Equal(t, 2, m.mapping.getCESCount(), "Total number of CESs allocated is 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs inserted is 1")
	})
	t.Run("Test reusing CES", func(*testing.T) {
		m := newCESManagerIdentity(2, log).(*cesManagerIdentity)
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
