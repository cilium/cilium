// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
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
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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
	var pod resource.Resource[*slim_corev1.Pod]
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
			jg := jr.NewGroup(h)
			lc.Append(jg)
			return jg
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
		cell.Invoke(func(c k8sClient.Clientset, p resource.Resource[*slim_corev1.Pod], ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) error {
			fakeClient = c
			pod = p
			ciliumEndpointSlice = ces
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cesCreated, err := createPodandVerifyCESCreated(fakeClient, pod, ciliumEndpointSlice)
	if err != nil {
		t.Fatalf("Couldn't verify if CES is created: %s", err)
	}
	// Verify CES is created when CES features is enabled
	assert.Equal(t, true, cesCreated)
	if err := hive.Stop(tlog, context.Background()); err != nil {
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
	var pod resource.Resource[*slim_corev1.Pod]
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
			jg := jr.NewGroup(h)
			lc.Append(jg)
			return jg
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
		cell.Invoke(func(c k8sClient.Clientset, p resource.Resource[*slim_corev1.Pod], ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) error {
			fakeClient = c
			pod = p
			ciliumEndpointSlice = ces
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cesCreated, err := createPodandVerifyCESCreated(fakeClient, pod, ciliumEndpointSlice)
	if err != nil {
		t.Fatalf("Couldn't verify if CES is created: %s", err)
	}
	// Verify CES is NOT created when CES features is disabled
	assert.Equal(t, false, cesCreated)
	if err = h.Stop(tlog, context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func createPodandVerifyCESCreated(fakeClient k8sClient.Clientset, pod resource.Resource[*slim_corev1.Pod], ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) (bool, error) {
	pod_store := tu.CreateStorePod("cep1", "ns", 1)
	fakeClient.Slim().CoreV1().Pods("ns").Create(context.Background(), pod_store, meta_v1.CreateOptions{}) //slim

	podStore, _ := pod.Store(context.Background())
	if err := testutils.WaitUntil(func() bool {
		return len(podStore.List()) > 0
	}, time.Second); err != nil {
		return false, fmt.Errorf("failed to get Pod: %w", err)
	}
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, time.Second)
	// err == nil means CES was created
	return err == nil, nil
}
