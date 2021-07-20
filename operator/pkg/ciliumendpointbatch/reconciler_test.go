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

	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/annotation"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
)

const (
	CEBReconcilerUID      = "12345"
	CEBReconcilerGenerate = 9090
)

var (
	// Test CEB object, with 2 CEPs packed in it.
	Ceb1 = &capi_v2a1.CiliumEndpointBatch{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointBatch",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "Ceb-apple-one",
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

	// Test CEB object, with 2 CEPs packed in it.
	Ceb2 = &capi_v2a1.CiliumEndpointBatch{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointBatch",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "Ceb-apple-two",
			Annotations: map[string]string{
				annotation.CiliumEndpointBatchQueueInfo: CEBatchingModeFcfs,
			},
		},
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{
			{
				Name:       "cilium-nfgt-123",
				Namespace:  "kube-system",
				IdentityID: 364748,
			},
			{
				Name:       "cilium-nfgt-456",
				Namespace:  "kube-system",
				IdentityID: 364748,
			},
		},
	}

	// Test CEB object, with 2 CEPs packed in it.
	Ceb3 = &capi_v2a1.CiliumEndpointBatch{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointBatch",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "Ceb-apple-three",
			Annotations: map[string]string{
				annotation.CiliumEndpointBatchQueueInfo: CEBatchingModeFcfs,
			},
		},
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{
			{
				Name:       "cilium-tkld-123",
				Namespace:  "kube-system",
				IdentityID: 364748,
			},
			{
				Name:       "cilium-tkld-456",
				Namespace:  "kube-system",
				IdentityID: 364748,
			},
		},
	}
)

// Create a fake cilium Client and add prepend reactor for Create/Update/Delete
func ciliumClient() clientset.CiliumV2alpha1Interface {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "ciliumendpointbatches", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		ciliumEndpointBatch := action.(k8stesting.CreateAction).GetObject().(*capi_v2a1.CiliumEndpointBatch)
		ciliumEndpointBatch.UID = CEBReconcilerUID
		return false, ciliumEndpointBatch, nil
	}))
	client.PrependReactor("update", "ciliumendpointbatches", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		ciliumEndpointBatch := action.(k8stesting.UpdateAction).GetObject().(*capi_v2a1.CiliumEndpointBatch)
		ciliumEndpointBatch.Generation = CEBReconcilerGenerate
		return false, ciliumEndpointBatch, nil
	}))
	client.PrependReactor("delete", "ciliumendpointbatches", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		return false, nil, nil
	}))
	return client.CiliumV2alpha1()
}

// Test Reconciler by creating CEBs, Updating CEBs and Deleting CEBs
func TestCiliumReconcile(t *testing.T) {
	var e []string
	client := ciliumClient()

	// Store the CEBs in local Datastore
	m := newCebManagerFcfs(newAggregator(), 2)
	// Create a CEB and updates the CEB in local datastore.
	// deepcopies the entire CEB object in datastore.
	m.createCeb(Ceb1.Name)
	m.updateCebInCache(Ceb1, true)
	m.createCeb(Ceb2.Name)
	m.updateCebInCache(Ceb2, true)
	m.createCeb(Ceb3.Name)
	m.updateCebInCache(Ceb3, true)

	// List of CEBs to be created in api-server
	cebCreate := []string{Ceb1.Name, Ceb2.Name, Ceb3.Name}
	r := newReconciler(client, m)

	// Create CEBs, check errors from api-server and match CEBs UID value returned
	// from api-server with CEBs in datastore.
	t.Run("Create CEBs, check for any errors and  compare returned value from api-server with local data", func(*testing.T) {
		ec, eu, ed := r.reconcileWithServer(cebCreate, e, e)
		// There should not be any errors from api-server
		assert.Equal(t, len(ec), 0, "Check if any CEBs failed to Create with api-server")
		assert.Equal(t, len(eu), 0, "Check if any CEBs failed to Update with api-server")
		assert.Equal(t, len(ed), 0, "Check if any CEBs failed to Delete with api-server")
		// Get Ceb from local datastore
		ceb, _ := m.getCebFromCache(Ceb1.Name)
		assert.Equal(t, string(ceb.GetUID()), CEBReconcilerUID, "Returned CEB UID from api-server should match with local CEB UID")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb2.Name)
		assert.Equal(t, string(ceb.GetUID()), CEBReconcilerUID, "Returned CEB UID from api-server should match with local CEB UID")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb2.Name)
		assert.Equal(t, string(ceb.GetUID()), CEBReconcilerUID, "Returned CEB UID from api-server should match with local CEB UID")
	})

	// Update CEBs, check errors from api-server and match CEBs Generate value returned
	// from api-server with CEBs in datastore.
	cebUpdate := []string{Ceb1.Name, Ceb2.Name, Ceb3.Name}
	t.Run("Update CEBs, check for any errors and  compare returned value from api-server with local data", func(*testing.T) {
		ec, eu, ed := r.reconcileWithServer(e, cebUpdate, e)
		// There should not be any errors from api-server
		assert.Equal(t, len(ec), 0, "Check if any CEBs failed to Create with api-server")
		assert.Equal(t, len(eu), 0, "Check if any CEBs failed to Update with api-server")
		assert.Equal(t, len(ed), 0, "Check if any CEBs failed to Delete with api-server")
		// Get Ceb from local datastore
		ceb, _ := m.getCebFromCache(Ceb1.Name)
		assert.Equal(t, ceb.Generation, int64(CEBReconcilerGenerate), "Returned CEB Generate from api-server should match with constant")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb2.Name)
		assert.Equal(t, ceb.Generation, int64(CEBReconcilerGenerate), "Returned CEB Generate from api-server should match with constant")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb2.Name)
		assert.Equal(t, ceb.Generation, int64(CEBReconcilerGenerate), "Returned CEB Generate from api-server should match with constant")
	})

	// Delete CEBs, check errors from api-server and match CEBs and CEPs count
	cebDelete := []string{Ceb1.Name, Ceb2.Name, Ceb3.Name}
	t.Run("Delete CEBs, check errors from api-server and match CEBs and CEPs count ", func(*testing.T) {
		// Get Cebs from local datastore and check it length
		assert.Equal(t, m.getCebCount(), 3, "Check the total CEB, this should match with value 3")
		assert.Equal(t, m.getCepCount(), 6, "Check the total CEB, this should match with value 6")

		// reconcile with Server
		ec, eu, ed := r.reconcileWithServer(e, e, cebDelete)

		// There should not be any errors from api-server
		assert.Equal(t, len(ec), 0, "No errors from Ceb Create")
		assert.Equal(t, len(eu), 0, "No errors from Ceb Update")
		assert.Equal(t, len(ed), 0, "No errors from Ceb Delete")

		// Get Ceb from local datastore
		assert.Equal(t, m.getCebCount(), 0, "No CEBs in datastore")
		assert.Equal(t, m.getCepCount(), 0, "No CEPs in datastore")
	})
}
