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
package ciliumendpointbatch

import (
	"testing"

	"github.com/cilium/cilium/pkg/annotation"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	cep1 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-123",
		Namespace:  "kube-system",
		IdentityID: 364747,
	}

	cep2 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-456",
		Namespace:  "kube-system",
		IdentityID: 364747,
	}

	cep3 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-abcd-789",
		Namespace:  "kube-system",
		IdentityID: 364747,
	}

	cep4 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-bcde-123",
		Namespace:  "kube-system",
		IdentityID: 364747,
	}

	cep5 = &capi_v2a1.CoreCiliumEndpoint{
		Name:       "cilium-bcde-456",
		Namespace:  "kube-system",
		IdentityID: 364747,
	}

	Ceb = &capi_v2a1.CiliumEndpointBatch{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointBatch",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Annotations: map[string]string{
				annotation.CiliumEndpointBatchQueueInfo: CEBatchingModeFcfs,
			},
		},
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{
			{
				Name:       "cilium-abcd-123",
				Namespace:  "kube-system",
				IdentityID: 364748,
			},
			{
				Name:       "cilium-abcd-456",
				Namespace:  "kube-system",
				IdentityID: 364748,
			},
		},
	}
)

func TestInsertAndRemoveCepsInCache(t *testing.T) {

	// Insert CEPs in Cache and count total number of CEB and CEP
	t.Run("Test Inserting CEPs in cache and count number of CEPs and CEBs", func(*testing.T) {
		m := newCebManagerFcfs(newAggregator(), 2)
		m.InsertCepInCache(cep1)
		m.InsertCepInCache(cep2)
		m.InsertCepInCache(cep3)
		assert.Equal(t, m.getCebCount(), 2, "Total number of CEBs allocated is 2")
		assert.Equal(t, m.getCepCount(), 3, "Total number of CEPs inserted is 3")
	})

	// Remove CEPs from Cache and check total number of CEB and CEP
	t.Run("Test Removing CEPs from cache and check number of CEPs and CEBs", func(*testing.T) {
		m := newCebManagerFcfs(newAggregator(), 2)
		u := newCepToCebMapping()
		cn, _ := m.InsertCepInCache(cep1)
		u.insert(cep1.Name, cn)
		cn, _ = m.InsertCepInCache(cep2)
		u.insert(cep2.Name, cn)
		cn, _ = m.InsertCepInCache(cep3)
		u.insert(cep3.Name, cn)
		cn, _ = m.InsertCepInCache(cep4)
		u.insert(cep4.Name, cn)
		cn, _ = m.InsertCepInCache(cep5)
		u.insert(cep5.Name, cn)
		// Check all 5 CEP are inserted
		assert.Equal(t, m.getCebCount(), 3, "Total number of CEBs allocated is 3")
		assert.Equal(t, m.getCepCount(), 5, "Total number of CEPs inserted is 5")

		// Remove a CEP from Cache
		// This should remove one CEP from cache and remove a CEB
		m.RemoveCepFromCache(cep5)
		if cn, ok := u.get(cep5.Name); ok {
			// complete CEB delete from local datastore, after successful removal in k8s-apiserver.
			m.deleteCebFromCache(cn)
		}
		assert.Equal(t, m.getCebCount(), 2, "Total number of CEBs allocated is 2")
		assert.Equal(t, m.getCepCount(), 4, "Total number of CEPs inserted is 4")

		// Remove a CEP from Cache
		// This should remove one CEP in a CEB.
		m.RemoveCepFromCache(cep3)
		assert.Equal(t, m.getCebCount(), 2, "Total number of CEBs allocated is 2")
		assert.Equal(t, m.getCepCount(), 3, "Total number of CEPs inserted is 3")

		// Remove a CEP from Cache
		// This should remove one CEP in a CEB.
		m.RemoveCepFromCache(cep4)
		if cn, ok := u.get(cep4.Name); ok {
			// complete CEB delete from local datastore, after successful removal in k8s-apiserver.
			m.deleteCebFromCache(cn)
		}
		assert.Equal(t, m.getCebCount(), 1, "Total number of CEBs allocated is 1")
		assert.Equal(t, m.getCepCount(), 2, "Total number of CEPs inserted is 2")

		// Remove a CEP from Cache
		// This should remove one CEP in a CEB.
		m.RemoveCepFromCache(cep1)
		assert.Equal(t, m.getCebCount(), 1, "Total number of CEBs allocated is 1")
		assert.Equal(t, m.getCepCount(), 1, "Total number of CEPs inserted is 1")

		// Remove a CEP from Cache
		// This should remove one CEP in a CEB.
		m.RemoveCepFromCache(cep2)
		if cn, ok := u.get(cep2.Name); ok {
			// complete CEB delete from local datastore, after successful removal in k8s-apiserver.
			m.deleteCebFromCache(cn)
		}
		assert.Equal(t, m.getCebCount(), 0, "Total number of CEBs allocated is 0")
		assert.Equal(t, m.getCepCount(), 0, "Total number of CEPs inserted is 0")
	})
}

func TestDeepCopyCeps(t *testing.T) {
	// Insert CEPs in Cache, then do the deep copy and compare CEBs.
	t.Run("Test Inserting CEPs in cache and count number of CEPs and CEBs", func(*testing.T) {
		m := newCebManagerFcfs(newAggregator(), 2)
		m.InsertCepInCache(cep1)
		cn, _ := m.InsertCepInCache(cep2)
		ceb, _ := m.getCebFromCache(cn)
		assert.Equal(t, m.getCebCount(), 1, "Total number of CEBs allocated is 1")
		assert.Equal(t, m.getCepCount(), 2, "Total number of CEPs inserted is 2")
		assert.Equal(t, m.getCepCount(), len(ceb.Endpoints), "Total number of CEPs inserted is 2")

		// Copy randomly Generated cebName to the local variable
		Ceb.Name = ceb.Name

		// Copy only headers and check data between local variable and in datastore. No DeepCopy.
		m.updateCebInCache(Ceb, false)
		ceb, _ = m.getCebFromCache(cn)
		assert.Equal(t, ceb.DeepEqual(Ceb), false, "This should fail, because CEP Identities are different")

		// do deep copy between local variable and in datastore
		m.updateCebInCache(Ceb, true)
		ceb, _ = m.getCebFromCache(cn)
		assert.Equal(t, ceb.DeepEqual(Ceb), true, "Local CEB should match with CEB in datastore")
	})
}
