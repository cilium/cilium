// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicegc

import (
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
)

func TestRegisterControllerOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requestSent := false
		hive := hive.New(
			k8sClient.FakeClientCell(),
			cell.Provide(func() ces.SharedConfig {
				return ces.SharedConfig{
					EnableCiliumEndpointSlice: false,
				}
			}),
			cell.Invoke(prepareCiliumEndpointSliceCRD),
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
			cell.Provide(func() ces.SharedConfig {
				return ces.SharedConfig{
					EnableCiliumEndpointSlice: true,
				}
			}),
			cell.Invoke(prepareCiliumEndpointSliceCRD),
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
