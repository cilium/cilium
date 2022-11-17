// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

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
	CESReconcilerUID      = "12345"
	CESReconcilerGenerate = 9090
)

var (
	// Test CES object, with 2 CEPs packed in it.
	CES1 = &capi_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "CES-apple-one",
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

	// Test CES object, with 2 CEPs packed in it.
	CES2 = &capi_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "CES-apple-two",
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

	// Test CES object, with 2 CEPs packed in it.
	CES3 = &capi_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "CES-apple-three",
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

	// Test CES object, with no CEPs packed in it.
	emptyCES = &capi_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: capi_v2a1.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "CES-empty",
		},
		Endpoints: []capi_v2a1.CoreCiliumEndpoint{},
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
	client.PrependReactor("create", "ciliumendpointslices", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		ciliumEndpointSlice := action.(k8stesting.CreateAction).GetObject().(*capi_v2a1.CiliumEndpointSlice)
		ciliumEndpointSlice.UID = CESReconcilerUID
		return false, ciliumEndpointSlice, nil
	}))
	client.PrependReactor("update", "ciliumendpointslices", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		ciliumEndpointSlice := action.(k8stesting.UpdateAction).GetObject().(*capi_v2a1.CiliumEndpointSlice)
		ciliumEndpointSlice.Generation = CESReconcilerGenerate
		return false, ciliumEndpointSlice, nil
	}))
	client.PrependReactor("delete", "ciliumendpointslices", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		return false, nil, nil
	}))
	return client.CiliumV2alpha1()
}

// Test Reconciler by creating CESs, Updating CESs and Deleting CESs
func TestCiliumReconcile(t *testing.T) {
	client := fakeCiliumClient()

	// Store the CESs in local Datastore
	m := newCESManagerFcfs(newQueue(), 2)
	// Create a CES and updates the CES in local datastore.
	// deepcopies the entire CES object in datastore.
	m.createCES(CES1.Name)
	m.updateCESInCache(CES1, true)
	m.createCES(CES2.Name)
	m.updateCESInCache(CES2, true)
	m.createCES(CES3.Name)
	m.updateCESInCache(CES3, true)

	// List of CESs to be created in api-server
	r := newReconciler(client, m)

	// Create CESs, check errors from api-server and match CESs UID value returned
	// from api-server with CESs in datastore.
	t.Run("Create CESs, check for any errors and  compare returned value from api-server with local data", func(*testing.T) {
		err := r.reconcileCESCreate(CES1.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Create request to api-server")
		err = r.reconcileCESCreate(CES2.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Create request to api-server")
		err = r.reconcileCESCreate(CES3.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Create request to api-server")
		// Get CES from local datastore
		ces, _ := m.getCESFromCache(CES1.Name)
		assert.Equal(t, string(ces.GetUID()), CESReconcilerUID, "Returned CES UID from api-server should match with local CES UID")
		// Get CES from local datastore
		ces, _ = m.getCESFromCache(CES2.Name)
		assert.Equal(t, string(ces.GetUID()), CESReconcilerUID, "Returned CES UID from api-server should match with local CES UID")
		// Get CES from local datastore
		ces, _ = m.getCESFromCache(CES3.Name)
		assert.Equal(t, string(ces.GetUID()), CESReconcilerUID, "Returned CES UID from api-server should match with local CES UID")
	})

	t.Run("Attempt to create empty CES and check that it is not created", func(*testing.T) {
		m.createCES(emptyCES.Name)
		m.updateCESInCache(emptyCES, true)
		err := r.reconcileCESCreate(emptyCES.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Create request to api-server")
		ces, _ := m.getCESFromCache(emptyCES.Name)
		// CES is empty, so it should be removed from cache instead of created in the api-server
		assert.Equal(t, (*capi_v2a1.CiliumEndpointSlice)(nil), ces, "Empty CES was removed from cache rather than created in api-server")
	})

	// Update CESs, check errors from api-server and match CESs Generate value returned
	// from api-server with CESs in datastore.
	t.Run("Update CESs, check for any errors and  compare returned value from api-server with local data", func(*testing.T) {
		err := r.reconcileCESUpdate(CES1.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Update request to api-server")
		err = r.reconcileCESUpdate(CES2.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Update request to api-server")
		err = r.reconcileCESUpdate(CES3.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Update request to api-server")
		// Get CES from local datastore
		ces, _ := m.getCESFromCache(CES1.Name)
		assert.Equal(t, ces.Generation, int64(CESReconcilerGenerate), "Returned CES Generate from api-server should match with constant")
		// Get CES from local datastore
		ces, _ = m.getCESFromCache(CES2.Name)
		assert.Equal(t, ces.Generation, int64(CESReconcilerGenerate), "Returned CES Generate from api-server should match with constant")
		// Get CES from local datastore
		ces, _ = m.getCESFromCache(CES3.Name)
		assert.Equal(t, ces.Generation, int64(CESReconcilerGenerate), "Returned CES Generate from api-server should match with constant")
	})

	// Delete CESs, check errors from api-server and match CESs and CEPs count
	t.Run("Delete CESs, check errors from api-server and match CESs and CEPs count ", func(*testing.T) {
		// Get CESs from local datastore and check it length
		assert.Equal(t, m.getCESCount(), 3, "Check the total CES, this should match with value 3")
		assert.Equal(t, m.getTotalCEPCount(), 6, "Check the total CES, this should match with value 6")

		// reconcile with Server
		err := r.reconcileCESDelete(CES1.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Delete request to api-server")
		err = r.reconcileCESDelete(CES2.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Delete request to api-server")
		err = r.reconcileCESDelete(CES3.Name)
		// There should not be any error from api-server
		assert.Equal(t, err, nil, "No error in CES Delete request to api-server")
	})
}
