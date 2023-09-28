// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"context"
	"testing"
	"time"

	"go.uber.org/goleak"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRegisterController(t *testing.T) {
	defer goleak.VerifyNone(
		t,
	)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				Interval:                 10 * time.Second,
				DisableCiliumEndpointCRD: false,
			}
		}),
		cell.Metric(NewMetrics),
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint]) {
			prepareCiliumEndpoints(*c)
			ciliumEndpoint = cep
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)
	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	// wait for all CEPs to be deleted except for those with running pods or
	// cilium node owner reference
	waitForCEPs(t, cepStore, 3)
	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestRegisterControllerOnce(t *testing.T) {
	defer goleak.VerifyNone(
		t,
	)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				Interval:                 0,
				DisableCiliumEndpointCRD: false,
			}
		}),
		cell.Metric(NewMetrics),
		cell.Invoke(prepareCiliumEndpointCRD),
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint]) {
			prepareCiliumEndpoints(*c)
			ciliumEndpoint = cep
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)
	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	// wait for all CEPs to be deleted
	waitForCEPs(t, cepStore, 0)
	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestRegisterControllerWithCRDDisabled(t *testing.T) {
	defer goleak.VerifyNone(
		t,
	)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Metric(NewMetrics),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				Interval:                 100 * time.Millisecond,
				DisableCiliumEndpointCRD: true,
			}
		}),
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint]) {
			prepareCiliumEndpoints(*c)
			ciliumEndpoint = cep
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)
	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	// wait for potential GC
	time.Sleep(500 * time.Millisecond)
	// gc is disabled so no CEPs should be deleted
	waitForCEPs(t, cepStore, 8)
	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func prepareCiliumEndpointCRD(c *k8sClient.FakeClientset) error {
	c.APIExtFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, nil
	})
	return nil
}

func prepareCiliumEndpoints(fakeClient k8sClient.FakeClientset) {
	// Create set of Cilium Endpoints:
	// - CEP with no owner reference and no pods
	cep := createCiliumEndpoint("cep1", "ns")
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cep, meta_v1.CreateOptions{})
	// - CEP with owner reference pod that is running
	cepWithOwnerRunningPod := createCiliumEndpoint("cep2", "ns")
	cepWithOwnerRunningPod.OwnerReferences = []meta_v1.OwnerReference{createOwnerReference("Pod", "pod2")}
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithOwnerRunningPod, meta_v1.CreateOptions{})
	// - CEP with owner reference pod that is not running
	cepWithOwnerNotRunningPod := createCiliumEndpoint("cep3", "ns")
	cepWithOwnerNotRunningPod.OwnerReferences = []meta_v1.OwnerReference{createOwnerReference("Pod", "pod3")}
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithOwnerNotRunningPod, meta_v1.CreateOptions{})
	// - CEP with no owner reference but with pod that is running
	cepWithLegacyRunningPod := createCiliumEndpoint("cep4", "ns")
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithLegacyRunningPod, meta_v1.CreateOptions{})
	// - CEP with no owner reference but with pod that is not running
	cepWithLegacyNotRunningPod := createCiliumEndpoint("cep5", "ns")
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithLegacyNotRunningPod, meta_v1.CreateOptions{})
	// - CEP with owner reference Cilium Node
	cepWithOwnerCiliumNode := createCiliumEndpoint("cep6", "ns")
	cepWithOwnerCiliumNode.OwnerReferences = []meta_v1.OwnerReference{createOwnerReference("CiliumNode", "node6")}
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithOwnerCiliumNode, meta_v1.CreateOptions{})
	// - CEP with owner reference pod that doesn't exist
	cepWithOwnerPodDoesntExist := createCiliumEndpoint("cep7", "ns")
	cepWithOwnerPodDoesntExist.OwnerReferences = []meta_v1.OwnerReference{createOwnerReference("Pod", "pod7")}
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithOwnerPodDoesntExist, meta_v1.CreateOptions{})
	// - CEP with owner reference cilium node that doesn't exist
	cepWithOwnerCiliumNodeDoesntExist := createCiliumEndpoint("cep8", "ns")
	cepWithOwnerCiliumNodeDoesntExist.OwnerReferences = []meta_v1.OwnerReference{createOwnerReference("CiliumNode", "node8")}
	fakeClient.CiliumV2().CiliumEndpoints("ns").Create(context.Background(), cepWithOwnerCiliumNodeDoesntExist, meta_v1.CreateOptions{})

	// Create Pods
	// - pod that is running for cep2
	fakeClient.Slim().CoreV1().Pods("ns").Create(context.Background(), createPod("pod2", "ns", true), meta_v1.CreateOptions{})
	// - pod that is not running for cep3
	fakeClient.Slim().CoreV1().Pods("ns").Create(context.Background(), createPod("pod3", "ns", false), meta_v1.CreateOptions{})
	// - pod that is running for cep4
	fakeClient.Slim().CoreV1().Pods("ns").Create(context.Background(), createPod("cep4", "ns", true), meta_v1.CreateOptions{})
	// - pod that is not running for cep5
	fakeClient.Slim().CoreV1().Pods("ns").Create(context.Background(), createPod("cep5", "ns", false), meta_v1.CreateOptions{})

	// Create CiliumNodes
	// - cilium node for cep6
	fakeClient.CiliumV2().CiliumNodes().Create(context.Background(), createCiliumNode("node6"), meta_v1.CreateOptions{})
}

func waitForCEPs(t *testing.T, cepStore resource.Store[*cilium_v2.CiliumEndpoint], number int) {
	if err := testutils.WaitUntil(func() bool {
		return len(cepStore.List()) == number
	}, 10*time.Second); err != nil {
		t.Fatalf("failed to reach expected number (%d) of CEPs: %s", number, err)
	}
}

func createCiliumEndpoint(name, namespace string) *cilium_v2.CiliumEndpoint {
	return &cilium_v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func createOwnerReference(kind, name string) meta_v1.OwnerReference {
	return meta_v1.OwnerReference{
		Kind: kind,
		Name: name,
	}
}

func createPod(name, namespace string, isRunning bool) *v1.Pod {
	var phase slim_corev1.PodPhase
	if isRunning {
		phase = slim_corev1.PodRunning
	} else {
		phase = slim_corev1.PodSucceeded
	}
	return &v1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: v1.PodStatus{
			Phase: phase,
		},
	}
}

func createCiliumNode(name string) *cilium_v2.CiliumNode {
	return &cilium_v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
	}
}
