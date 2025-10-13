// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicegc

import (
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRegisterControllerOnce(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
	)
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: false,
			}
		}),
		cell.Invoke(prepareCiliumEndpointSliceCRD),
		cell.Invoke(func(c *k8sClient.FakeClientset, ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) {
			prepareCiliumEndpointSlices(t, c)
			ciliumEndpointSlice = ces
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	// wait for all CESs to be deleted
	waitForCESs(t, cesStore, 0)
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestRegisterControllerWithCESEnabled(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
	)
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: true,
			}
		}),
		cell.Invoke(func(c *k8sClient.FakeClientset, ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) {
			prepareCiliumEndpointSlices(t, c)
			ciliumEndpointSlice = ces
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	// wait for potential GC
	time.Sleep(500 * time.Millisecond)
	// gc is disabled so no CESs should be deleted
	waitForCESs(t, cesStore, 3)
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func prepareCiliumEndpointSliceCRD(c *k8sClient.FakeClientset) error {
	c.APIExtFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, nil
	})
	return nil
}

func prepareCiliumEndpointSlices(t *testing.T, fakeClient *k8sClient.FakeClientset) {
	ces := createCiliumEndpointSlice("ces1", "ns")
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces, meta_v1.CreateOptions{})

	ces2 := createCiliumEndpointSlice("ces2", "ns")
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces2, meta_v1.CreateOptions{})

	ces3 := createCiliumEndpointSlice("ces3", "ns")
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces3, meta_v1.CreateOptions{})
}

func waitForCESs(t *testing.T, cesStore resource.Store[*cilium_v2a1.CiliumEndpointSlice], number int) {
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Len(c, cesStore.List(), number)
	}, 2*time.Second, 10*time.Millisecond, "failed to reach expected number (%d) of CESs", number)
}

func createCiliumEndpointSlice(name, namespace string) *cilium_v2a1.CiliumEndpointSlice {
	return &cilium_v2a1.CiliumEndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}
