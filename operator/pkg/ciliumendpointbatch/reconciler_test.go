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

package ciliumendpointbatch

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"

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
		},
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

	// Test CEB object, with 2 CEPs packed in it.
	Ceb2 = &capi_v2a1.CiliumEndpointBatch{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointBatch",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "Ceb-apple-two",
		},
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{
			{
				Name:       "cilium-nfgt-123",
				IdentityID: 364748,
			},
			{
				Name:       "cilium-nfgt-456",
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
		},
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{
			{
				Name:       "cilium-tkld-123",
				IdentityID: 364748,
			},
			{
				Name:       "cilium-tkld-456",
				IdentityID: 364748,
			},
		},
	}
)

func newQueue() workqueue.RateLimitingInterface {
	return workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(5), 10)}), "fakeQueue")
}

// Create a fake cilium Client and add prepend reactor for Create/Update/Delete
func fakeCiliumClient() clientset.CiliumV2alpha1Interface {
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
	client := fakeCiliumClient()

	// Store the CEBs in local Datastore
	m := newCebManagerFcfs(newQueue(), 2)
	// Create a CEB and updates the CEB in local datastore.
	// deepcopies the entire CEB object in datastore.
	m.createCeb(Ceb1.Name)
	m.updateCebInCache(Ceb1, true)
	m.createCeb(Ceb2.Name)
	m.updateCebInCache(Ceb2, true)
	m.createCeb(Ceb3.Name)
	m.updateCebInCache(Ceb3, true)

	// List of CEBs to be created in api-server
	r := newReconciler(client, m)

	// Create CEBs, check errors from api-server and match CEBs UID value returned
	// from api-server with CEBs in datastore.
	t.Run("Create CEBs, check for any errors and  compare returned value from api-server with local data", func(*testing.T) {
		err := r.reconcileCebCreate(Ceb1.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Create request to api-server")
		err = r.reconcileCebCreate(Ceb2.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Create request to api-server")
		err = r.reconcileCebCreate(Ceb3.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Create request to api-server")
		// Get Ceb from local datastore
		ceb, _ := m.getCebFromCache(Ceb1.Name)
		assert.Equal(t, string(ceb.GetUID()), CEBReconcilerUID, "Returned CEB UID from api-server should match with local CEB UID")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb2.Name)
		assert.Equal(t, string(ceb.GetUID()), CEBReconcilerUID, "Returned CEB UID from api-server should match with local CEB UID")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb3.Name)
		assert.Equal(t, string(ceb.GetUID()), CEBReconcilerUID, "Returned CEB UID from api-server should match with local CEB UID")
	})

	// Update CEBs, check errors from api-server and match CEBs Generate value returned
	// from api-server with CEBs in datastore.
	t.Run("Update CEBs, check for any errors and  compare returned value from api-server with local data", func(*testing.T) {
		err := r.reconcileCebUpdate(Ceb1.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Update request to api-server")
		err = r.reconcileCebUpdate(Ceb2.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Update request to api-server")
		err = r.reconcileCebUpdate(Ceb3.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Update request to api-server")
		// Get Ceb from local datastore
		ceb, _ := m.getCebFromCache(Ceb1.Name)
		assert.Equal(t, ceb.Generation, int64(CEBReconcilerGenerate), "Returned CEB Generate from api-server should match with constant")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb2.Name)
		assert.Equal(t, ceb.Generation, int64(CEBReconcilerGenerate), "Returned CEB Generate from api-server should match with constant")
		// Get Ceb from local datastore
		ceb, _ = m.getCebFromCache(Ceb3.Name)
		assert.Equal(t, ceb.Generation, int64(CEBReconcilerGenerate), "Returned CEB Generate from api-server should match with constant")
	})

	// Delete CEBs, check errors from api-server and match CEBs and CEPs count
	t.Run("Delete CEBs, check errors from api-server and match CEBs and CEPs count ", func(*testing.T) {
		// Get Cebs from local datastore and check it length
		assert.Equal(t, m.getCebCount(), 3, "Check the total CEB, this should match with value 3")
		assert.Equal(t, m.getTotalCepCount(), 6, "Check the total CEB, this should match with value 6")

		// reconcile with Server
		err := r.reconcileCebDelete(Ceb1.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Delete request to api-server")
		err = r.reconcileCebDelete(Ceb2.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Delete request to api-server")
		err = r.reconcileCebDelete(Ceb3.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CEB Delete request to api-server")
	})
}
