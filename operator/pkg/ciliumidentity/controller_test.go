// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	WaitUntilTimeout = 5 * time.Second
)

func TestRegisterControllerWithOperatorManagingCIDs(t *testing.T) {
	cidResource, cesResource, fakeClient, h := initHiveTest(true)

	ctx := context.Background()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}

	if err := createNsAndPod(ctx, fakeClient); err != nil {
		t.Errorf("Failed to create namespace or pod: %v", err)
	}

	cidStore, _ := (*cidResource).Store(ctx)
	err := testutils.WaitUntil(func() bool { return len(cidStore.List()) > 0 }, WaitUntilTimeout)
	if err != nil {
		t.Errorf("Expected CID to be created, got %v", err)
	}

	if err := verifyCIDUsageInCES(ctx, fakeClient, *cidResource, *cesResource); err != nil {
		t.Errorf("Failed to verify CID usage in CES, got %v", err)
	}

	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

func TestRegisterController(t *testing.T) {
	cidResource, _, fakeClient, h := initHiveTest(false)

	ctx := context.Background()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}

	if err := createNsAndPod(ctx, fakeClient); err != nil {
		t.Errorf("Failed to create namespace or pod: %v", err)
	}

	cidStore, _ := (*cidResource).Store(ctx)
	if len(cidStore.List()) != 0 {
		t.Errorf("Expected no CIDs to be present in the store, but found %d", len(cidStore.List()))
	}

	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

func initHiveTest(operatorManagingCID bool) (*resource.Resource[*capi_v2.CiliumIdentity], *resource.Resource[*capi_v2a1.CiliumEndpointSlice], *k8sClient.FakeClientset, *hive.Hive) {
	var cidResource resource.Resource[*capi_v2.CiliumIdentity]
	var cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]
	var fakeClient k8sClient.FakeClientset
	h := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableOperatorManageCIDs:  operatorManagingCID,
				EnableCiliumEndpointSlice: true,
			}
		}),
		cell.Provide(func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
			h := p.ForModule(cell.FullModuleID{"test"})
			jg := jr.NewGroup(h)
			lc.Append(jg)
			return jg
		}),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cid resource.Resource[*capi_v2.CiliumIdentity],
			ces resource.Resource[*capi_v2a1.CiliumEndpointSlice],
		) error {
			fakeClient = *c
			cidResource = cid
			cesResource = ces
			return nil
		}),
	)
	return &cidResource, &cesResource, &fakeClient, h
}

func createNsAndPod(ctx context.Context, fakeClient *k8sClient.FakeClientset) error {
	ns := testCreateNSObj("ns1", nil)
	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return err
	}
	pod := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	if _, err := fakeClient.Slim().CoreV1().Pods("ns1").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func verifyCIDUsageInCES(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]) error {
	cidStore, _ := cidResource.Store(ctx)
	cids := cidStore.List()
	if len(cids) == 0 {
		return fmt.Errorf("no CIDs found in the store")
	}

	cidNum, err := strconv.Atoi(cids[0].Name)
	if err != nil {
		return err
	}

	cep1 := cestest.CreateManagerEndpoint("cep1", int64(cidNum))
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1})
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces1, metav1.CreateOptions{}); err != nil {
		return err
	}

	cesStore, _ := cesResource.Store(context.Background())
	if err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, WaitUntilTimeout); err != nil {
		return fmt.Errorf("failed to get CES: %w", err)
	}

	// CID is not deleted even when Pod is, because the CID is still used in CES.
	if err := fakeClient.Slim().CoreV1().Pods("ns1").Delete(ctx, "pod1", metav1.DeleteOptions{}); err != nil {
		return err
	}

	if len(cidStore.List()) == 0 {
		return fmt.Errorf("expected for CID to not be deleted")
	}

	if err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, ces1.Name, metav1.DeleteOptions{}); err != nil {
		return err
	}

	return nil
}
