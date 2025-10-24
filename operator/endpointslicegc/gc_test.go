// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicegc

import (
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
)

func TestRegisterControllerOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requestSent := false
		hive := hive.New(
			k8sClient.FakeClientCell(),
			k8s.ResourcesCell,
			cell.Provide(func() ces.SharedConfig {
				return ces.SharedConfig{
					EnableCiliumEndpointSlice: false,
				}
			}),
			cell.Invoke(prepareCiliumEndpointSliceCRD),
			cell.Invoke(func(c *k8sClient.FakeClientset) {
				prepareCiliumEndpointSlices(t, c)
			}),
			cell.Invoke(func(c *k8sClient.FakeClientset) error {
				c.CiliumFakeClientset.PrependReactor(
					"delete-collection",
					"ciliumendpointslices",
					func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
						requestSent = true
						return true, nil, nil
					},
				)
				return nil
			}),
			cell.Invoke(func(p params) {
				registerGC(p)
			}),
		)

		tlog := hivetest.Logger(t)
		if err := hive.Start(tlog, t.Context()); err != nil {
			t.Fatalf("failed to start: %s", err)
		}

		synctest.Wait()
		assert.True(t, requestSent)

		if err := hive.Stop(tlog, t.Context()); err != nil {
			t.Fatalf("failed to stop: %s", err)
		}
	})
}

func TestRegisterControllerWithCESEnabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		noRequest := true
		hive := hive.New(
			k8sClient.FakeClientCell(),
			k8s.ResourcesCell,
			cell.Provide(func() ces.SharedConfig {
				return ces.SharedConfig{
					EnableCiliumEndpointSlice: true,
				}
			}),
			cell.Invoke(prepareCiliumEndpointSliceCRD),
			cell.Invoke(func(c *k8sClient.FakeClientset) {
				prepareCiliumEndpointSlices(t, c)
			}),
			cell.Invoke(func(c *k8sClient.FakeClientset) error {
				// There should be no requests from the GC when CES is enabled.
				c.CiliumFakeClientset.PrependReactor(
					"*",
					"*",
					func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
						noRequest = false
						return true, nil, nil
					},
				)
				return nil
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

		synctest.Wait()
		assert.True(t, noRequest)

		if err := hive.Stop(tlog, t.Context()); err != nil {
			t.Fatalf("failed to stop: %s", err)
		}
	})
}

func prepareCiliumEndpointSliceCRD(c *k8sClient.FakeClientset) error {
	c.APIExtFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, nil
	})
	return nil
}

func prepareCiliumEndpointSlices(t *testing.T, fakeClient *k8sClient.FakeClientset) {
	ces := createCiliumEndpointSlice("ces1", "ns")
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces, meta_v1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create CiliumEndpointSlice: %s", err)
	}

	ces2 := createCiliumEndpointSlice("ces2", "ns")
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces2, meta_v1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create CiliumEndpointSlice: %s", err)
	}

	ces3 := createCiliumEndpointSlice("ces3", "ns")
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces3, meta_v1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create CiliumEndpointSlice: %s", err)
	}
}

func createCiliumEndpointSlice(name, namespace string) *cilium_v2a1.CiliumEndpointSlice {
	return &cilium_v2a1.CiliumEndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}
