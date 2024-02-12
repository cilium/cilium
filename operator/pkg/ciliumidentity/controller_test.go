// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/cilium/operator/k8s"
	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ignoreWorkqueueGoroutineLeak(t *testing.T) {
	goleak.VerifyNone(
		t,
		// To ignore goroutine started by the workqueue. It reports metrics
		// on unfinished work with default tick period of 0.5s - it terminates
		// no longer than 0.5s after the workqueue is stopped.
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*Type).updateUnfinishedWorkLoop"),
	)
}

func TestRegisterController(t *testing.T) {
	testInitLabelsFilter()
	defer ignoreWorkqueueGoroutineLeak(t)

	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*capi_v2.CiliumIdentity]
	var ciliumEndpointSlice resource.Resource[*capi_v2a1.CiliumEndpointSlice]
	var fakeClient k8sClient.FakeClientset
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(func() Config {
			return defaultConfig
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableOperatorManageCIDs:  true,
				EnableCiliumEndpointSlice: true,
			}
		}),
		cell.Metric(NewMetrics),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			nsResource resource.Resource[*slim_corev1.Namespace],
			podResource resource.Resource[*slim_corev1.Pod],
			cidResource resource.Resource[*capi_v2.CiliumIdentity],
			cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice],
		) error {
			fakeClient = *c
			namespace = nsResource
			ciliumIdentity = cidResource
			ciliumEndpointSlice = cesResource
			return nil
		}),
	)
	ctx := context.Background()
	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	verified, err := createPodAndVerifyCIDIsCreated(ctx, &fakeClient, ciliumIdentity, namespace)
	assert.NoError(t, err)
	assert.Equal(t, true, verified)

	verified, err = verifyCIDUsageInCES(ctx, &fakeClient, ciliumIdentity, ciliumEndpointSlice)
	assert.NoError(t, err)
	assert.Equal(t, true, verified)

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestRegisterControllerFeatureDisabled(t *testing.T) {
	testInitLabelsFilter()
	defer ignoreWorkqueueGoroutineLeak(t)

	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*capi_v2.CiliumIdentity]
	var ciliumEndpointSlice resource.Resource[*capi_v2a1.CiliumEndpointSlice]
	var fakeClient k8sClient.FakeClientset
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(func() Config {
			return defaultConfig
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableOperatorManageCIDs:  false,
				EnableCiliumEndpointSlice: true,
			}
		}),
		cell.Metric(NewMetrics),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			nsResource resource.Resource[*slim_corev1.Namespace],
			podResource resource.Resource[*slim_corev1.Pod],
			cidResource resource.Resource[*capi_v2.CiliumIdentity],
			cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice],
		) error {
			fakeClient = *c
			namespace = nsResource
			ciliumIdentity = cidResource
			ciliumEndpointSlice = cesResource
			return nil
		}),
	)
	ctx := context.Background()
	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	verified, err := createPodAndVerifyCIDIsCreated(ctx, &fakeClient, ciliumIdentity, namespace)
	assert.NoError(t, err)
	assert.Equal(t, false, verified)

	verified, err = verifyCIDUsageInCES(ctx, &fakeClient, ciliumIdentity, ciliumEndpointSlice)
	assert.NoError(t, err)
	assert.Equal(t, false, verified)

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func createPodAndVerifyCIDIsCreated(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], nsResource resource.Resource[*slim_corev1.Namespace]) (bool, error) {
	// Verified is true only when the CID controller does all the expected actions.
	verified := false

	ns := testCreateNSObj("ns1", nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return verified, err
	}

	pod := testCreatePodObj("pod1", "ns1", testLblsA, nil)
	_, err = fakeClient.Slim().CoreV1().Pods("ns1").Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return verified, err
	}

	cidStore, _ := cidResource.Store(ctx)
	err = testutils.WaitUntil(func() bool {
		return len(cidStore.List()) > 0
	}, time.Second)

	verified = err == nil
	return verified, nil
}

func verifyCIDUsageInCES(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]) (bool, error) {
	// Verified is true only when the CID controller does all the expected actions.
	verified := false

	cidStore, _ := cidResource.Store(ctx)
	cids := cidStore.List()
	if len(cids) == 0 {
		return verified, nil
	}

	cidNum, err := strconv.Atoi(cids[0].Name)
	if err != nil {
		return verified, err
	}

	cep1 := cestest.CreateManagerEndpoint("cep1", int64(cidNum))
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1})
	_, err = fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces1, metav1.CreateOptions{})
	if err != nil {
		return verified, err
	}

	cesStore, _ := cesResource.Store(context.Background())
	if err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, time.Second); err != nil {
		return verified, fmt.Errorf("failed to get CES: %s", err)
	}

	// CID is not deleted even when Pod is, because the CID is still used in CES.
	err = fakeClient.Slim().CoreV1().Pods("ns1").Delete(ctx, "pod1", metav1.DeleteOptions{})
	if err != nil {
		return verified, err
	}

	if len(cidStore.List()) == 0 {
		return verified, fmt.Errorf("expected for CID to not be deleted")
	}

	err = fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, ces1.Name, metav1.DeleteOptions{})
	if err != nil {
		return verified, err
	}

	err = testutils.WaitUntil(func() bool {
		return len(cidStore.List()) == 0
	}, time.Second)

	verified = err == nil
	return verified, nil
}
