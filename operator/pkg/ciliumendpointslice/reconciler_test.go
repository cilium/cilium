// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"
	
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
)

func TestReconcileCreate(t *testing.T) {
	m := newCESManagerFcfs(2).(*cesManagerFcfs)
	c, _ := client.NewFakeClientset()

	var createdSlice *v2alpha1.CiliumEndpointSlice
	c.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*v2alpha1.CiliumEndpointSlice)
		return true, nil, nil
	})
	r := newReconciler(c.CiliumFakeClientset.CiliumV2alpha1(), m)
	r.ciliumEndpointStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ceSliceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	r.ciliumEndpointStore.Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	r.ciliumEndpointStore.Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	r.ciliumEndpointStore.Add(cep3)
	m.mapping.insertCES("ces1", "ns")
	m.mapping.insertCES("ces2", "ns")
	m.mapping.insertCEP("ns/cep1", "ces1")
	m.mapping.insertCEP("ns/cep2", "ces1")
	m.mapping.insertCEP("ns/cep3", "ces2")
	r.reconcileCES("ces1")

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Equal(t, 2, len(createdSlice.Endpoints))
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")
}

func TestReconcileUpdate(t *testing.T) {
	m := newCESManagerFcfs(2).(*cesManagerFcfs)
	c, _ := client.NewFakeClientset()

	var updatedSlice *v2alpha1.CiliumEndpointSlice
	c.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*v2alpha1.CiliumEndpointSlice)
		return true, nil, nil
	})
	r := newReconciler(c.CiliumFakeClientset.CiliumV2alpha1(), m)
	r.ciliumEndpointStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ceSliceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	r.ciliumEndpointStore.Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	r.ciliumEndpointStore.Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	r.ciliumEndpointStore.Add(cep3)
	ces1 := createStoreEndpointSlice("ces1", "ns", []v2alpha1.CoreCiliumEndpoint{createManagerEndpoint("cep1", 1), createManagerEndpoint("cep3", 2)})
	ceSliceStore.Add(ces1)
	m.mapping.insertCES("ces1", "ns")
	m.mapping.insertCES("ces2", "ns")
	m.mapping.insertCEP("ns/cep1", "ces1")
	m.mapping.insertCEP("ns/cep2", "ces1")
	m.mapping.insertCEP("ns/cep3", "ces2")
	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES("ces1")

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Equal(t, 2, len(updatedSlice.Endpoints))
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")
}

func TestReconcileDelete(t *testing.T) {
	m := newCESManagerFcfs(2).(*cesManagerFcfs)
	c, _ := client.NewFakeClientset()

	var deletedSlice string
	c.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})
	r := newReconciler(c.CiliumFakeClientset.CiliumV2alpha1(), m)
	r.ciliumEndpointStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ceSliceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	r.ciliumEndpointStore.Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	r.ciliumEndpointStore.Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	r.ciliumEndpointStore.Add(cep3)
	ces1 := createStoreEndpointSlice("ces1", "ns", []v2alpha1.CoreCiliumEndpoint{createManagerEndpoint("cep1", 1), createManagerEndpoint("cep3", 2)})
	ceSliceStore.Add(ces1)
	m.mapping.insertCES("ces1", "ns")
	m.mapping.insertCES("ces2", "ns")
	m.mapping.insertCEP("ns/cep1", "ces2")
	m.mapping.insertCEP("ns/cep2", "ces2")
	m.mapping.insertCEP("ns/cep3", "ces2")
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES("ces1")

	assert.Equal(t, "ces1", deletedSlice)
}

func TestReconcileNoop(t *testing.T) {
	m := newCESManagerFcfs(2).(*cesManagerFcfs)
	c, _ := client.NewFakeClientset()

	noRequest := true
	c.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})
	r := newReconciler(c.CiliumFakeClientset.CiliumV2alpha1(), m)
	r.ciliumEndpointStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ceSliceStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	r.ciliumEndpointStore.Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	r.ciliumEndpointStore.Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	r.ciliumEndpointStore.Add(cep3)
	m.mapping.insertCES("ces1", "ns")
	m.mapping.insertCES("ces2", "ns")
	m.mapping.insertCEP("ns/cep1", "ces2")
	m.mapping.insertCEP("ns/cep2", "ces2")
	m.mapping.insertCEP("ns/cep3", "ces2")
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES("ces1")

	assert.Equal(t, true, noRequest)
}
