// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/annotation"
)

func newFakeConnectivityTest(t *testing.T, objects ...runtime.Object) (*ConnectivityTest, *k8s.Client) {
	t.Helper()

	client := &k8s.Client{
		Clientset: fake.NewSimpleClientset(objects...),
	}

	ct := &ConnectivityTest{
		params: Parameters{
			TestNamespace:        "default-test-namespace",
			Writer:               &bytes.Buffer{},
			NamespaceLabels:      map[string]string{"suite": "connectivity"},
			NamespaceAnnotations: map[string]string{"owner": "test"},
			CurlImage:            "quay.io/cilium/alpine-curl:latest",
		},
		Features: features.Set{
			features.DefaultGlobalNamespace: {Enabled: false},
		},
		clients: &deploymentClients{
			src: client,
			dst: client,
		},
	}

	return ct, client
}

func TestDeployNamespaceCreatesMissingNamespace(t *testing.T) {
	ct, client := newFakeConnectivityTest(t)

	err := ct.deployNamespace(context.Background(), client, "created-ns")
	require.NoError(t, err)

	namespace, err := client.GetNamespace(context.Background(), "created-ns", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "created-ns", namespace.Name)
	assert.Equal(t, "connectivity", namespace.Labels["suite"])
	assert.Equal(t, "cilium-cli", namespace.Labels["app.kubernetes.io/name"])
	assert.Equal(t, "test", namespace.Annotations["owner"])
	assert.Equal(t, "true", namespace.Annotations[annotation.GlobalNamespace])
}

func TestDeployNamespaceUpdatesExistingNamespace(t *testing.T) {
	existing := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "existing-ns",
			Annotations: map[string]string{"existing": "annotation"},
			Labels:      map[string]string{"existing": "label"},
		},
	}
	ct, client := newFakeConnectivityTest(t, existing)

	err := ct.deployNamespace(context.Background(), client, "existing-ns")
	require.NoError(t, err)

	namespace, err := client.GetNamespace(context.Background(), "existing-ns", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "annotation", namespace.Annotations["existing"])
	assert.Equal(t, "true", namespace.Annotations[annotation.GlobalNamespace])
	assert.Equal(t, "label", namespace.Labels["existing"])
}

func TestDeployNamespaceUsesProvidedNamespaceName(t *testing.T) {
	ct, client := newFakeConnectivityTest(t)
	ct.params.TestNamespace = "wrong-ns"

	err := ct.deployNamespace(context.Background(), client, "actual-ns")
	require.NoError(t, err)

	_, err = client.GetNamespace(context.Background(), "actual-ns", metav1.GetOptions{})
	require.NoError(t, err)

	_, err = client.GetNamespace(context.Background(), "wrong-ns", metav1.GetOptions{})
	assert.Error(t, err)
}

func TestDeployCCNPTestEnvCreatesNamespacesAndDeployments(t *testing.T) {
	ct, client := newFakeConnectivityTest(t)

	err := ct.deployCCNPTestEnv(context.Background())
	require.NoError(t, err)

	for _, namespaceName := range []string{ccnpTestNamespace1, ccnpTestNamespace2} {
		namespace, err := client.GetNamespace(context.Background(), namespaceName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, "true", namespace.Annotations[annotation.GlobalNamespace])

		serviceAccount, err := client.GetServiceAccount(context.Background(), namespaceName, ccnpDeploymentName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, ccnpDeploymentName, serviceAccount.Name)

		deployment, err := client.GetDeployment(context.Background(), namespaceName, ccnpDeploymentName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, ccnpDeploymentName, deployment.Name)
		assert.Equal(t, kindCCNPName, deployment.Labels["kind"])
	}
}
