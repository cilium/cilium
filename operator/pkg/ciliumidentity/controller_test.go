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
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
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
	testCases := []struct {
		name                     string
		enableOperatorManageCIDs bool
		expectCESError           bool
	}{
		{
			name:                     "Enabled",
			enableOperatorManageCIDs: true,
			expectCESError:           false,
		},
		{
			name:                     "Disabled",
			enableOperatorManageCIDs: false,
			expectCESError:           true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cidResource resource.Resource[*capi_v2.CiliumIdentity]
			var cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]
			var fakeClient k8sClient.FakeClientset
			h := hive.New(
				k8sClient.FakeClientCell,
				k8s.ResourcesCell,
				cell.Provide(func() SharedConfig {
					return SharedConfig{
						EnableOperatorManageCIDs:  tc.enableOperatorManageCIDs,
						EnableCiliumEndpointSlice: true,
					}
				}),
				cell.Provide(NewMetrics),
				cell.Invoke(func(p params) error {
					registerController(p)
					return nil
				}),
				cell.Invoke(func(
					c *k8sClient.FakeClientset,
					_ resource.Resource[*slim_corev1.Namespace],
					podResource resource.Resource[*slim_corev1.Pod],
					cid resource.Resource[*capi_v2.CiliumIdentity],
					ces resource.Resource[*capi_v2a1.CiliumEndpointSlice],
				) error {
					fakeClient = *c
					cidResource = cid
					cesResource = ces
					return nil
				}),
			)

			ctx := context.Background()
			tlog := hivetest.Logger(t)
			if err := h.Start(tlog, ctx); err != nil {
				t.Fatalf("starting hive encountered an error: %s", err)
			}

			verified, err := createPodAndVerifyCIDIsCreated(ctx, &fakeClient, cidResource)
			if err != nil {
				t.Errorf("unexpected error when creating pod and verifying CIDs: %v", err)
			}
			if verified != tc.enableOperatorManageCIDs {
				t.Errorf("expected CID Is Created to be %v, but got %v", tc.enableOperatorManageCIDs, verified)
			}

			verified, err = verifyCIDUsageInCES(ctx, &fakeClient, cidResource, cesResource)
			if tc.expectCESError {
				if err == nil {
					t.Error("expected error when verifying CID usage in CES, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error when verifying CID usage in CES: %v", err)
				}
			}

			if verified != tc.enableOperatorManageCIDs {
				t.Errorf("expected verified to be %v, but got %v", tc.enableOperatorManageCIDs, verified)
			}

			if err := h.Stop(tlog, ctx); err != nil {
				t.Fatalf("stopping hive encountered an error: %v", err)
			}

			ignoreWorkqueueGoroutineLeak(t)
		})
	}
}

func createPodAndVerifyCIDIsCreated(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity]) (bool, error) {
	ns := testCreateNSObj("ns1", nil)
	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return false, err
	}

	pod := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	if _, err := fakeClient.Slim().CoreV1().Pods("ns1").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return false, err
	}

	cidStore, _ := cidResource.Store(ctx)
	err := testutils.WaitUntil(func() bool {
		return len(cidStore.List()) > 0
	}, time.Second)

	return err == nil, nil
}

func verifyCIDUsageInCES(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]) (bool, error) {
	cidStore, _ := cidResource.Store(ctx)
	cids := cidStore.List()
	if len(cids) == 0 {
		return false, fmt.Errorf("no CIDs found in the store")
	}

	cidNum, err := strconv.Atoi(cids[0].Name)
	if err != nil {
		return false, err
	}

	cep1 := cestest.CreateManagerEndpoint("cep1", int64(cidNum))
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1})
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces1, metav1.CreateOptions{}); err != nil {
		return false, err
	}

	cesStore, _ := cesResource.Store(context.Background())
	if err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, time.Second); err != nil {
		return false, fmt.Errorf("failed to get CES: %s", err)
	}

	// CID is not deleted even when Pod is, because the CID is still used in CES.
	if err := fakeClient.Slim().CoreV1().Pods("ns1").Delete(ctx, "pod1", metav1.DeleteOptions{}); err != nil {
		return false, err
	}

	if len(cidStore.List()) == 0 {
		return false, fmt.Errorf("expected for CID to not be deleted")
	}

	if err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, ces1.Name, metav1.DeleteOptions{}); err != nil {
		return false, err
	}

	// Temporarily reduce delete delay during test.
	oldDelay := cidDeleteDelay
	cidDeleteDelay = 100 * time.Millisecond
	err = testutils.WaitUntil(func() bool {
		return len(cidStore.List()) == 0
	}, time.Second)
	cidDeleteDelay = oldDelay

	return err == nil, nil
}
