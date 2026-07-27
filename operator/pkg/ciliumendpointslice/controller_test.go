// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	idtu "github.com/cilium/cilium/operator/pkg/ciliumidentity/testutils"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
	wgAgent "github.com/cilium/cilium/pkg/wireguard/agent"
)

func TestRegisterController(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	var fakeClient k8sClient.Clientset
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	hive := hive.New(
		k8sFakeClient.FakeClientBuilderCell(),
		k8s.ResourcesCell,
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
		cell.Provide(func() Config {
			return defaultConfig
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: true,
			}
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
	defer testutils.GoleakVerifyNone(
		t,
		// To ignore goroutine started by the workqueue. It reports metrics
		// on unfinished work with default tick period of 0.5s - it terminates
		// no longer than 0.5s after the workqueue is stopped.
		testutils.GoleakIgnoreTopFunction("k8s.io/client-go/util/workqueue.(*Type).updateUnfinishedWorkLoop"),
	)
	var fakeClient k8sClient.Clientset
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	h := hive.New(
		k8sFakeClient.FakeClientBuilderCell(),
		k8s.ResourcesCell,
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
		cell.Provide(func() Config {
			return defaultConfig
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: false,
			}
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

func TestRegisterControllerNoCEPs(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	fakeClient, pod, ciliumEndpointSlice, namespace, ciliumNode, ciliumIdentity, _, hive := initHiveTest(t, true, true)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	labelsfilter.ParseLabelPrefixCfg(tlog, nil, nil, "")

	cesCreated, err := createPodandVerifyCESCreated(t, fakeClient, pod, ciliumEndpointSlice, namespace, ciliumIdentity, ciliumNode)

	if err != nil {
		t.Fatalf("Couldn't verify if CES is created: %s", err)
	}

	assert.True(t, cesCreated)
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func createPodandVerifyCESCreated(t *testing.T, fakeClient k8sClient.Clientset, pod resource.Resource[*slim_corev1.Pod], ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice], ns resource.Resource[*slim_corev1.Namespace], cid resource.Resource[*cilium_v2.CiliumIdentity], cnode resource.Resource[*cilium_v2.CiliumNode]) (bool, error) {
	// Create a node, with pod1 (in ns with labels tu.TestLbsA)
	node := tu.CreateStoreNode("node1")
	fakeClient.CiliumV2().CiliumNodes().Create(t.Context(), node, meta_v1.CreateOptions{})

	ns1 := idtu.NewNamespace("ns", nil)
	fakeClient.Slim().CoreV1().Namespaces().Create(t.Context(), ns1, meta_v1.CreateOptions{})

	pod1 := idtu.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	fakeClient.Slim().CoreV1().Pods("ns").Create(t.Context(), pod1, meta_v1.CreateOptions{})

	id1 := idtu.NewCID("1", tu.TestLbsA)
	_, err := fakeClient.CiliumV2().CiliumIdentities().Create(t.Context(), id1, meta_v1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to create CiliumIdentity: %w", err)
	}

	// Verify whether CES is created after pod creation
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	err = testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, time.Second)

	return err == nil, nil
}

func initHiveTest(t *testing.T, enableCES, enableCESwithoutCEPs bool) (k8sClient.Clientset, resource.Resource[*slim_corev1.Pod], resource.Resource[*cilium_v2a1.CiliumEndpointSlice], resource.Resource[*slim_corev1.Namespace], resource.Resource[*cilium_v2.CiliumNode], resource.Resource[*cilium_v2.CiliumIdentity], *Metrics, *hive.Hive) {
	var fakeClient k8sClient.Clientset
	var pod resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics

	hive := hive.New(
		k8sFakeClient.FakeClientBuilderCell(),
		k8s.ResourcesCell,
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
		cell.Provide(func() Config {
			config := defaultConfig
			if enableCESwithoutCEPs {
				config.CESControllerMode = slimMode
			}
			return config
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: enableCES,
			}
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
		cell.Invoke(func(
			c k8sClient.Clientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			ns resource.Resource[*slim_corev1.Namespace],
			cnode resource.Resource[*cilium_v2.CiliumNode],
			cid resource.Resource[*cilium_v2.CiliumIdentity],
			m *Metrics) error {
			fakeClient = c
			pod = p
			ciliumEndpointSlice = ces
			namespace = ns
			ciliumNode = cnode
			ciliumIdentity = cid
			cesMetrics = m
			return nil
		}),
	)
	if err := hive.Populate(hivetest.Logger(t)); err != nil {
		t.Fatalf("failed to populate hive: %s", err)
	}
	return fakeClient, pod, ciliumEndpointSlice, namespace, ciliumNode, ciliumIdentity, cesMetrics, hive
}
