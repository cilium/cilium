// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRegisterController(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// To ignore goroutine started by the workqueue. It reports metrics
		// on unfinished work with default tick period of 0.5s - it terminates
		// no longer than 0.5s after the workqueue is stopped.
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*Typed[...]).updateUnfinishedWorkLoop"),
	)
	var fakeClient k8sClient.Clientset
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	hive := hive.New(
		k8sClient.FakeClientBuilderCell,
		k8s.ResourcesCell,
		cell.Provide(func() Config {
			return defaultConfig
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: true,
			}
		}),
		cell.Provide(func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
			h := p.ForModule(cell.FullModuleID{"test"})
			return jr.NewGroup(h, lc)
		}),
		metrics.Metric(NewMetrics),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Provide(func(f k8sClient.ClientBuilderFunc) k8sClient.Clientset {
			clientset, _ := f("test-ces-registered")
			return clientset
		}),
		cell.Invoke(func(c k8sClient.Clientset, cep resource.Resource[*cilium_v2.CiliumEndpoint], ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cesCreated, err := createCEPandVerifyCESCreated(t, fakeClient, ciliumEndpoint, ciliumEndpointSlice)
	if err != nil {
		t.Fatalf("Couldn't verify if CES is created: %s", err)
	}
	// Verify CES is created when CES features is enabled
	assert.True(t, cesCreated)
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestNotRegisterControllerWithCESDisabled(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// To ignore goroutine started by the workqueue. It reports metrics
		// on unfinished work with default tick period of 0.5s - it terminates
		// no longer than 0.5s after the workqueue is stopped.
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*Type).updateUnfinishedWorkLoop"),
	)
	var fakeClient k8sClient.Clientset
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	h := hive.New(
		k8sClient.FakeClientBuilderCell,
		k8s.ResourcesCell,
		cell.Provide(func() Config {
			return defaultConfig
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: false,
			}
		}),
		cell.Provide(func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
			h := p.ForModule(cell.FullModuleID{"test"})
			return jr.NewGroup(h, lc)
		}),
		metrics.Metric(NewMetrics),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Provide(func(f k8sClient.ClientBuilderFunc) k8sClient.Clientset {
			clientset, _ := f("test-ces-unregistered")
			return clientset
		}),
		cell.Invoke(func(c k8sClient.Clientset, cep resource.Resource[*cilium_v2.CiliumEndpoint], ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cesCreated, err := createCEPandVerifyCESCreated(t, fakeClient, ciliumEndpoint, ciliumEndpointSlice)
	if err != nil {
		t.Fatalf("Couldn't verify if CES is created: %s", err)
	}
	// Verify CES is NOT created when CES features is disabled
	assert.False(t, cesCreated)
	if err = h.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func createCEPandVerifyCESCreated(t *testing.T, fakeClient k8sClient.Clientset, ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint], ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) (bool, error) {
	cep := tu.CreateStoreEndpoint("cep1", "ns", 1)
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(t.Context(), cep, meta_v1.CreateOptions{})
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	if err := testutils.WaitUntil(func() bool {
		return len(cepStore.List()) > 0
	}, time.Second); err != nil {
		return false, fmt.Errorf("failed to get CEP: %w", err)
	}
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())

	err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, time.Second)
	// err == nil means CES was created
	return err == nil, nil
}
