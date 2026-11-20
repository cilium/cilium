// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/cilium/operator/pkg/gateway-api/crds"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

// TestIntegrationInstallCRDs validates the CRD lifecycle against a real
// apiserver, pointed to by KUBECONFIG. It must not contain any Gateway API
// CRDs, which are removed at the end of the test.
func TestIntegrationInstallCRDs(t *testing.T) {
	testutils.IntegrationTest(t)
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("Set KUBECONFIG to run this test")
	}

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	cs, err := apiextensionsclient.NewForConfig(restConfig)
	require.NoError(t, err)
	dyn, err := dynamic.NewForConfig(restConfig)
	require.NoError(t, err)
	crdClient := cs.ApiextensionsV1().CustomResourceDefinitions()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	targets, err := bundledCRDs()
	require.NoError(t, err)
	for _, target := range targets {
		_, err := crdClient.Get(ctx, target.Name, metav1.GetOptions{})
		if !k8serrors.IsNotFound(err) {
			t.Skipf("CRD %s already present in the cluster (err: %v), refusing to run", target.Name, err)
		}
	}
	t.Cleanup(func() {
		for _, target := range targets {
			crdClient.Delete(context.Background(), target.Name, metav1.DeleteOptions{})
		}
	})

	install := func() *cell.SimpleHealth {
		t.Helper()
		targets, err := bundledCRDs()
		require.NoError(t, err)
		health, simpleHealth := cell.NewSimpleHealth()
		require.NoError(t, installCRDs(ctx, hivetest.Logger(t), cs, health, targets))
		return simpleHealth
	}
	get := func(name string) *apiextensionsv1.CustomResourceDefinition {
		t.Helper()
		crd, err := crdClient.Get(ctx, name, metav1.GetOptions{})
		require.NoError(t, err)
		return crd
	}
	resourceVersions := func() map[string]string {
		rv := map[string]string{}
		for _, target := range targets {
			rv[target.Name] = get(target.Name).ResourceVersion
		}
		return rv
	}

	// Fresh installation: all CRDs are created and established.
	require.Equal(t, cell.StatusOK, install().Level)
	for _, target := range targets {
		crd := get(target.Name)
		require.Equal(t, crdManagedByValue, crd.Labels[crdManagedByLabel])
		require.Equal(t, target.Annotations[crds.BundleVersionAnnotation], crd.Annotations[crds.BundleVersionAnnotation])
		established := false
		for _, cond := range crd.Status.Conditions {
			if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
				established = true
			}
		}
		require.True(t, established, "%s is not established", crd.Name)
	}

	// Restart: no write is performed.
	before := resourceVersions()
	require.Equal(t, cell.StatusOK, install().Level)
	require.Equal(t, before, resourceVersions())

	// A custom resource survives an upgrade of its CRD.
	httpRouteGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "test", "namespace": "default"},
		"spec":       map[string]any{"hostnames": []any{"example.com"}},
	}}
	require.Eventually(t, func() bool {
		_, err := dyn.Resource(httpRouteGVR).Namespace("default").Create(ctx, route, metav1.CreateOptions{})
		return err == nil || k8serrors.IsAlreadyExists(err)
	}, time.Minute, time.Second)

	// Upgrade of a managed CRD from an older version.
	old := get("httproutes.gateway.networking.k8s.io")
	old.Annotations[crds.BundleVersionAnnotation] = "v1.5.0"
	old.Annotations["example.com/keep"] = "true"
	old.Spec.Versions[0].Schema.OpenAPIV3Schema.Description = "older schema"
	_, err = crdClient.Update(ctx, old, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Equal(t, cell.StatusOK, install().Level)
	upgraded := get("httproutes.gateway.networking.k8s.io")
	require.Equal(t, crdManagedByValue, upgraded.Labels[crdManagedByLabel])
	require.Equal(t, targets[0].Annotations[crds.BundleVersionAnnotation], upgraded.Annotations[crds.BundleVersionAnnotation])
	require.Equal(t, "true", upgraded.Annotations["example.com/keep"])
	require.NotEqual(t, "older schema", upgraded.Spec.Versions[0].Schema.OpenAPIV3Schema.Description)
	_, err = dyn.Resource(httpRouteGVR).Namespace("default").Get(ctx, "test", metav1.GetOptions{})
	require.NoError(t, err)

	// An older externally managed CRD is reported, but not modified.
	external := get("gateways.gateway.networking.k8s.io")
	delete(external.Labels, crdManagedByLabel)
	external.Annotations[crds.BundleVersionAnnotation] = "v1.5.0"
	external, err = crdClient.Update(ctx, external, metav1.UpdateOptions{})
	require.NoError(t, err)

	health := install()
	require.Equal(t, cell.StatusDegraded, health.Level)
	require.Equal(t, external.ResourceVersion, get("gateways.gateway.networking.k8s.io").ResourceVersion)

	// Handing the CRD over to the operator resolves the conflict.
	if external.Labels == nil {
		external.Labels = map[string]string{}
	}
	external.Labels[crdManagedByLabel] = crdManagedByValue
	_, err = crdClient.Update(ctx, external, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Equal(t, cell.StatusOK, install().Level)
	require.Equal(t, targets[0].Annotations[crds.BundleVersionAnnotation], get("gateways.gateway.networking.k8s.io").Annotations[crds.BundleVersionAnnotation])

	// An upgrade refused by the apiserver, as it would drop a stored version,
	// is reported but doesn't fail the operator.
	udp := get("udproutes.gateway.networking.k8s.io")
	stored := *udp.Spec.Versions[0].DeepCopy()
	stored.Name = "v1test"
	for i := range udp.Spec.Versions {
		udp.Spec.Versions[i].Storage = false
	}
	stored.Storage = true
	udp.Spec.Versions = append(udp.Spec.Versions, stored)
	udp.Annotations[crds.BundleVersionAnnotation] = "v1.5.0"
	udp, err = crdClient.Update(ctx, udp, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Contains(t, udp.Status.StoredVersions, "v1test")

	health = install()
	require.Equal(t, cell.StatusDegraded, health.Level)
	require.Equal(t, "v1.5.0", get("udproutes.gateway.networking.k8s.io").Annotations[crds.BundleVersionAnnotation])
}
