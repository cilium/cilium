// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"strconv"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	cidtest "github.com/cilium/cilium/operator/pkg/ciliumidentity/testutils"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/metrics"
)

func TestReconcileCreateDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)

	var createdSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Len(t, createdSlice.Endpoints, 2)
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileUpdateDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)

	var updatedSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1, "node1"), tu.CreateManagerEndpoint("cep3", 2, "node2")})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Len(t, updatedSlice.Endpoints, 2)
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileDeleteDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)

	var deletedSlice string
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1, "node1"), tu.CreateManagerEndpoint("cep3", 2, "node3")})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(tlog, t.Context())
}

func TestReconcileDeleteEmptiesCESFirst(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(100, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)
	r.emptyBeforeDeleteThreshold = 3

	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		written := action.(k8sTesting.UpdateAction).GetObject().(*cilium_v2a1.CiliumEndpointSlice).DeepCopy()
		written.ResourceVersion = "6"
		return true, written, nil
	})
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})

	endpoints := make([]cilium_v2a1.CoreCiliumEndpoint, 0, 3)
	for i := range 3 {
		endpoints = append(endpoints, tu.CreateManagerEndpoint("cep"+strconv.Itoa(i), int64(i+1), "node1"))
	}
	ces := tu.CreateStoreEndpointSlice("ces1", "ns", endpoints)
	ces.UID = types.UID("uid-ces1")
	ces.ResourceVersion = "5"
	cesStore.CacheStore().Add(ces)
	m.mapping.insertCES(CESName("ces1"), "ns")

	assert.NoError(t, r.reconcileCES(t.Context(), CESName("ces1")))

	var writes []k8sTesting.Action
	for _, action := range fakeClient.CiliumFakeClientset.Actions() {
		if action.GetResource().Resource == "ciliumendpointslices" {
			switch action.GetVerb() {
			case "create", "update", "delete":
				writes = append(writes, action)
			}
		}
	}
	assert.Len(t, writes, 2)

	assert.Equal(t, "update", writes[0].GetVerb())
	emptied := writes[0].(k8sTesting.UpdateAction).GetObject().(*cilium_v2a1.CiliumEndpointSlice)
	assert.Equal(t, "ces1", emptied.Name)
	assert.Equal(t, "ns", emptied.Namespace)
	assert.Equal(t, "5", emptied.ResourceVersion, "the update must be based on the version in the store")
	assert.NotNil(t, emptied.Endpoints, "endpoints is a required field")
	assert.Empty(t, emptied.Endpoints)

	assert.Equal(t, "delete", writes[1].GetVerb())
	del := writes[1].(k8sTesting.DeleteAction)
	assert.Equal(t, "ces1", del.GetName())
	pre := del.GetDeleteOptions().Preconditions
	assert.NotNil(t, pre, "the delete must be limited to the emptied version")
	assert.Equal(t, types.UID("uid-ces1"), *pre.UID)
	assert.Equal(t, "6", *pre.ResourceVersion)

	// The object in the store must not have been modified.
	assert.Len(t, ces.Endpoints, 3)

	assert.NoError(t, hive.Stop(tlog, t.Context()))
}

func TestReconcileDeleteSmallCESDirectly(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int
		endpoints int
	}{
		{name: "below threshold", threshold: 10, endpoints: 9},
		{name: "disabled", threshold: 0, endpoints: 100},
		{name: "negative threshold", threshold: -1, endpoints: 100},
		{name: "no endpoints", threshold: 1, endpoints: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r *defaultReconciler
			var fakeClient *k8sClient.FakeClientset
			m := newDefaultManager(100, hivetest.Logger(t))
			var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
			var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
			var cesMetrics *Metrics
			hive := hive.New(
				k8sClient.FakeClientCell(),
				k8s.ResourcesCell,
				metrics.Metric(NewMetrics),
				cell.Invoke(func(
					c *k8sClient.FakeClientset,
					cep resource.Resource[*cilium_v2.CiliumEndpoint],
					ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
					metrics *Metrics,
				) error {
					fakeClient = c
					ciliumEndpoint = cep
					ciliumEndpointSlice = ces
					cesMetrics = metrics
					return nil
				}),
			)

			tlog := hivetest.Logger(t)
			hive.Start(tlog, t.Context())
			cepStore, _ := ciliumEndpoint.Store(t.Context())
			cesStore, _ := ciliumEndpointSlice.Store(t.Context())
			r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)
			r.emptyBeforeDeleteThreshold = tc.threshold

			fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
				written := action.(k8sTesting.UpdateAction).GetObject().(*cilium_v2a1.CiliumEndpointSlice).DeepCopy()
				written.ResourceVersion = "6"
				return true, written, nil
			})
			fakeClient.CiliumFakeClientset.PrependReactor("delete", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
				return true, nil, nil
			})

			endpoints := make([]cilium_v2a1.CoreCiliumEndpoint, 0, tc.endpoints)
			for i := range tc.endpoints {
				endpoints = append(endpoints, tu.CreateManagerEndpoint("cep"+strconv.Itoa(i), int64(i+1), "node1"))
			}
			ces := tu.CreateStoreEndpointSlice("ces1", "ns", endpoints)
			ces.UID = types.UID("uid-ces1")
			ces.ResourceVersion = "5"
			cesStore.CacheStore().Add(ces)
			m.mapping.insertCES(CESName("ces1"), "ns")

			assert.NoError(t, r.reconcileCES(t.Context(), CESName("ces1")))

			var writes []k8sTesting.Action
			for _, action := range fakeClient.CiliumFakeClientset.Actions() {
				if action.GetResource().Resource == "ciliumendpointslices" {
					switch action.GetVerb() {
					case "create", "update", "delete":
						writes = append(writes, action)
					}
				}
			}
			assert.Len(t, writes, 1)
			assert.Equal(t, "delete", writes[0].GetVerb())
			del := writes[0].(k8sTesting.DeleteAction)
			assert.Equal(t, "ces1", del.GetName())
			assert.Nil(t, del.GetDeleteOptions().Preconditions)

			assert.NoError(t, hive.Stop(tlog, t.Context()))
		})
	}
}

func TestReconcileDeleteEmptyingFails(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(100, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)
	r.emptyBeforeDeleteThreshold = 1

	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewConflict(schema.GroupResource{Group: "cilium.io", Resource: "ciliumendpointslices"}, "ces1", nil)
	})
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})

	endpoints := make([]cilium_v2a1.CoreCiliumEndpoint, 0, 5)
	for i := range 5 {
		endpoints = append(endpoints, tu.CreateManagerEndpoint("cep"+strconv.Itoa(i), int64(i+1), "node1"))
	}
	ces := tu.CreateStoreEndpointSlice("ces1", "ns", endpoints)
	ces.UID = types.UID("uid-ces1")
	ces.ResourceVersion = "5"
	cesStore.CacheStore().Add(ces)
	m.mapping.insertCES(CESName("ces1"), "ns")

	// The error is returned so that the CES is reconciled again, and the CES
	// is not deleted with its endpoints still listed.
	err := r.reconcileCES(t.Context(), CESName("ces1"))
	assert.Error(t, err)
	assert.True(t, k8serrors.IsConflict(err))

	var writes []k8sTesting.Action
	for _, action := range fakeClient.CiliumFakeClientset.Actions() {
		if action.GetResource().Resource == "ciliumendpointslices" {
			switch action.GetVerb() {
			case "create", "update", "delete":
				writes = append(writes, action)
			}
		}
	}
	assert.Len(t, writes, 1)
	assert.Equal(t, "update", writes[0].GetVerb())

	assert.NoError(t, hive.Stop(tlog, t.Context()))
}

// TestReconcileDeleteRetryAfterEmptied covers a failure between the two
// writes: the CES has been written empty, but the delete (limited to that
// version) fails. The error must be returned, and the retry, which sees the
// emptied version in the store, must delete the CES directly, without
// writing it again.
func TestReconcileDeleteRetryAfterEmptied(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(100, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)
	r.emptyBeforeDeleteThreshold = 3

	fakeClient.CiliumFakeClientset.PrependReactor("update", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		written := action.(k8sTesting.UpdateAction).GetObject().(*cilium_v2a1.CiliumEndpointSlice).DeepCopy()
		written.ResourceVersion = "6"
		return true, written, nil
	})
	deletes := 0
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "ciliumendpointslices", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		deletes++
		if deletes == 1 {
			return true, nil, k8serrors.NewConflict(schema.GroupResource{Group: "cilium.io", Resource: "ciliumendpointslices"}, "ces1", nil)
		}
		return true, nil, nil
	})

	endpoints := make([]cilium_v2a1.CoreCiliumEndpoint, 0, 5)
	for i := range 5 {
		endpoints = append(endpoints, tu.CreateManagerEndpoint("cep"+strconv.Itoa(i), int64(i+1), "node1"))
	}
	ces := tu.CreateStoreEndpointSlice("ces1", "ns", endpoints)
	ces.UID = types.UID("uid-ces1")
	ces.ResourceVersion = "5"
	cesStore.CacheStore().Add(ces)
	m.mapping.insertCES(CESName("ces1"), "ns")

	err := r.reconcileCES(t.Context(), CESName("ces1"))
	assert.Error(t, err)
	assert.True(t, k8serrors.IsConflict(err))

	cesWrites := func() []k8sTesting.Action {
		var writes []k8sTesting.Action
		for _, action := range fakeClient.CiliumFakeClientset.Actions() {
			if action.GetResource().Resource == "ciliumendpointslices" {
				switch action.GetVerb() {
				case "create", "update", "delete":
					writes = append(writes, action)
				}
			}
		}
		return writes
	}

	writes := cesWrites()
	assert.Len(t, writes, 2)
	assert.Equal(t, "update", writes[0].GetVerb())
	assert.Equal(t, "delete", writes[1].GetVerb())
	assert.NotNil(t, writes[1].(k8sTesting.DeleteAction).GetDeleteOptions().Preconditions)

	// The informer delivers the emptied version before the retry.
	emptied := writes[0].(k8sTesting.UpdateAction).GetObject().(*cilium_v2a1.CiliumEndpointSlice).DeepCopy()
	emptied.ResourceVersion = "6"
	assert.NoError(t, cesStore.CacheStore().Update(emptied))

	assert.NoError(t, r.reconcileCES(t.Context(), CESName("ces1")))
	writes = cesWrites()
	assert.Len(t, writes, 3, "the retry must not write the CES again")
	assert.Equal(t, "delete", writes[2].GetVerb())
	del := writes[2].(k8sTesting.DeleteAction)
	assert.Equal(t, "ces1", del.GetName())
	assert.Nil(t, del.GetDeleteOptions().Preconditions)

	assert.NoError(t, hive.Stop(tlog, t.Context()))
}

func TestReconcileNoopDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cepStore, cesStore, cesMetrics)

	noRequest := true
	fakeClient.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.True(t, noRequest)

	hive.Stop(tlog, t.Context())
}

func TestReconcileCreate(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	labelsfilter.ParseLabelPrefixCfg(tlog, nil, nil, "")

	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	var createdSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)

	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)

	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsC, "node1")
	podStore.CacheStore().Add(pod3)
	cid3 := cidtest.NewCIDWithNamespace("3", pod3, ns1)
	cidStore.CacheStore().Add(cid3)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")

	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	_, gidC := cidToGidLabels(cid3)

	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.insertCID("3", gidC)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces1"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces1"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidC)

	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Len(t, createdSlice.Endpoints, 2)
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "pod1")
	assert.Contains(t, eps, "pod2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileUpdate(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	var updatedSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)

	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)

	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod3)

	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("pod1", 1, "node1"), tu.CreateManagerEndpoint("pod3", 2, "node1")})
	cesStore.CacheStore().Add(ces1)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")

	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces1"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces1"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidB)

	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Len(t, updatedSlice.Endpoints, 2)
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "pod1")
	assert.Contains(t, eps, "pod2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileDelete(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	var deletedSlice string
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)

	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)
	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod3)

	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1, "node1"), tu.CreateManagerEndpoint("cep3", 2, "node1")})
	cesStore.CacheStore().Add(ces1)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces2"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces2"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidB)

	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(tlog, t.Context())
}

func TestReconcileNoop(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	noRequest := true
	fakeClient.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)
	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)
	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod3)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces2"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces2"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidB)

	// ces1 is mapped to nothing so it won't be reconciled
	r.reconcileCES(t.Context(), CESName("ces1"))

	assert.True(t, noRequest)

	hive.Stop(tlog, t.Context())
}
