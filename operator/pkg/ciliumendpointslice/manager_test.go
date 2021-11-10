// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !privileged_tests
// +build !privileged_tests

package ciliumendpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	cep1 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-123",
		IdentityID: 364747,
	}

	cep2 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-456",
		IdentityID: 364748,
	}

	cep3 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-789",
		IdentityID: 364749,
	}

	cep4 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-bcde-123",
		IdentityID: 364757,
	}

	cep5 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-bcde-456",
		IdentityID: 364767,
	}

	cep1a = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-123a",
		IdentityID: 364747,
	}

	cep2b = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-456b",
		IdentityID: 364748,
	}

	CES = &capi_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{},
		Namespace:  "kube-system",
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{
			{
				Name:       "cilium-abcd-123",
				IdentityID: 364748,
			},
			{
				Name:       "cilium-abcd-456",
				IdentityID: 364748,
			},
		},
	}
)

func TestInsertAndRemoveCEPsInCache(t *testing.T) {

	// Insert CEPs in Cache and count total number of CES and CEP
	t.Run("Test Inserting CEPs in cache and count number of CEPs and CESs", func(*testing.T) {
		m := newCESManagerFcfs(newQueue(), 2)
		m.InsertCEPInCache(cep1, "kube-system")
		m.InsertCEPInCache(cep2, "kube-system")
		m.InsertCEPInCache(cep3, "kube-system")
		assert.Equal(t, m.getCESCount(), 2, "Total number of CESs allocated is 2")
		assert.Equal(t, m.getTotalCEPCount(), 3, "Total number of CEPs inserted is 3")
	})

	// Remove CEPs from Cache and check total number of CES and CEP
	t.Run("Test Removing CEPs from cache and check number of CEPs and CESs", func(*testing.T) {
		m := newCESManagerFcfs(newQueue(), 2)
		u := newDesiredCESMap()
		cn := m.InsertCEPInCache(cep1, "kube-system")
		u.insertCEP(cep1.Name, cn)
		cn = m.InsertCEPInCache(cep2, "kube-system")
		u.insertCEP(cep2.Name, cn)
		cn = m.InsertCEPInCache(cep3, "kube-system")
		u.insertCEP(cep3.Name, cn)
		cn = m.InsertCEPInCache(cep4, "kube-system")
		u.insertCEP(cep4.Name, cn)
		cn = m.InsertCEPInCache(cep5, "kube-system")
		u.insertCEP(cep5.Name, cn)
		// Check all 5 CEP are inserted
		assert.Equal(t, m.getCESCount(), 3, "Total number of CESs allocated is 3")
		assert.Equal(t, m.getTotalCEPCount(), 5, "Total number of CEPs inserted is 5")

		// Remove a CEP from Cache
		// This should remove one CEP from cache and remove a CES
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep5, "kube-system"), DefaultCESSyncTime)
		if cn, ok := u.getCESName(cep5.Name); ok {
			// complete CES delete from local datastore, after successful removal in k8s-apiserver.
			m.deleteCESFromCache(cn)
		}
		assert.Equal(t, m.getCESCount(), 2, "Total number of CESs allocated is 2")
		assert.Equal(t, m.getTotalCEPCount(), 4, "Total number of CEPs inserted is 4")

		// Remove a CEP from Cache
		// This should remove one CEP in a CES.
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep3, "kube-system"), DefaultCESSyncTime)
		assert.Equal(t, m.getCESCount(), 2, "Total number of CESs allocated is 2")
		assert.Equal(t, m.getTotalCEPCount(), 3, "Total number of CEPs inserted is 3")

		// Remove a CEP from Cache
		// This should remove one CEP in a CES.
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep4, "kube-system"), DefaultCESSyncTime)
		if cn, ok := u.getCESName(cep4.Name); ok {
			// complete CES delete from local datastore, after successful removal in k8s-apiserver.
			m.deleteCESFromCache(cn)
		}
		assert.Equal(t, m.getCESCount(), 1, "Total number of CESs allocated is 1")
		assert.Equal(t, m.getTotalCEPCount(), 2, "Total number of CEPs inserted is 2")

		// Remove a CEP from Cache
		// This should remove one CEP in a CES.
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep1, "kube-system"), DefaultCESSyncTime)
		assert.Equal(t, m.getCESCount(), 1, "Total number of CESs allocated is 1")
		assert.Equal(t, m.getTotalCEPCount(), 1, "Total number of CEPs inserted is 1")

		// Remove a CEP from Cache
		// This should remove one CEP in a CES.
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep2, "kube-system"), DefaultCESSyncTime)
		if cn, ok := u.getCESName(cep2.Name); ok {
			// complete CES delete from local datastore, after successful removal in k8s-apiserver.
			m.deleteCESFromCache(cn)
		}
		assert.Equal(t, m.getCESCount(), 0, "Total number of CESs allocated is 0")
		assert.Equal(t, m.getTotalCEPCount(), 0, "Total number of CEPs inserted is 0")
	})
}

func TestDeepCopyCEPs(t *testing.T) {
	// Insert CEPs in Cache, then do the deep copy and compare CESs.
	t.Run("Test Inserting CEPs in cache and count number of CEPs and CESs", func(*testing.T) {
		m := newCESManagerFcfs(newQueue(), 2)
		m.InsertCEPInCache(cep1, "kube-system")
		cn := m.InsertCEPInCache(cep2, "kube-system")
		ces, _ := m.getCESFromCache(cn)
		assert.Equal(t, m.getCESCount(), 1, "Total number of CESs allocated is 1")
		assert.Equal(t, m.getTotalCEPCount(), 2, "Total number of CEPs inserted is 2")
		assert.Equal(t, m.getTotalCEPCount(), len(ces.Endpoints), "Total number of CEPs inserted is 2")

		// Copy randomly Generated cesName to the local variable
		CES.Name = ces.Name

		// Copy only headers and check data between local variable and in datastore. No DeepCopy.
		m.updateCESInCache(CES, false)
		ces, _ = m.getCESFromCache(cn)
		assert.Equal(t, ces.DeepEqual(CES), false, "CEPs expected to have same name but different identities")

		// do deep copy between local variable and in datastore
		m.updateCESInCache(CES, true)
		ces, _ = m.getCESFromCache(cn)
		assert.Equal(t, ces.DeepEqual(CES), true, "Local CES should match with CES in datastore")

		m1 := newCESManagerIdentity(newQueue(), 2)
		m1.InsertCEPInCache(cep1, "kube-system")
		m1.InsertCEPInCache(cep1a, "kube-system")
		m1.InsertCEPInCache(cep2b, "kube-system")
		cn = m1.InsertCEPInCache(cep2, "kube-system")
		ces, _ = m1.getCESFromCache(cn)
		assert.Equal(t, m1.getCESCount(), 2, "Total number of CESs allocated is 2")
		assert.Equal(t, m1.getTotalCEPCount(), 4, "Total number of CEPs inserted is 4")
		assert.Equal(t, len(ces.Endpoints), 2, "Total number of CEPs inserted in a CES is 2")

		// Copy randomly Generated cesName to the local variable
		CES.Name = ces.Name

		// Copy only headers and check data between local variable and in datastore. No DeepCopy.
		m1.updateCESInCache(CES, false)
		ces, _ = m1.getCESFromCache(cn)
		assert.Equal(t, ces.DeepEqual(CES), false, "CEPs expected to have same name but different identities")

		// do deep copy between local variable and in datastore
		m1.updateCESInCache(CES, true)
		ces, _ = m1.getCESFromCache(cn)
		assert.Equal(t, ces.DeepEqual(CES), true, "Local CES should match with CES in datastore")
	})
}

func TestRemovedCEPs(t *testing.T) {
	t.Run("Test Deleting CEPs and Insert", func(*testing.T) {
		m := newCESManagerFcfs(newQueue(), 2)
		m.InsertCEPInCache(cep1, "kube-system")
		cesName := m.InsertCEPInCache(cep2, "kube-system")
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep1, "kube-system"), DefaultCESSyncTime)
		m.RemoveCEPFromCache(GetCEPNameFromCCEP(cep2, "kube-system"), DefaultCESSyncTime)
		remCEPs := m.getRemovedCEPs(cesName)
		assert.Equal(t, len(remCEPs), 2, "Total removedCEPs should match with value 2")
		m.clearRemovedCEPs(cesName, remCEPs)
		remCEPs = m.getRemovedCEPs(cesName)
		assert.Equal(t, len(remCEPs), 0, "Total removedCEPs should match with value 0")
	})
}
