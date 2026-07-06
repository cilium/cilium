// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/getter"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

func Test_getClusterName(t *testing.T) {
	assert.Empty(t, getClusterName(nil))

	opts := values.Options{}
	vals, err := opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Empty(t, getClusterName(vals))

	opts = values.Options{JSONValues: []string{"cluster={}"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Empty(t, getClusterName(vals))

	opts = values.Options{Values: []string{"cluster.name=my-cluster"}}
	vals, err = opts.MergeValues(getter.All(cli.New()))
	assert.NoError(t, err)
	assert.Equal(t, "my-cluster", getClusterName(vals))
}

func Test_trimEKSClusterName(t *testing.T) {
	vals := ""
	assert.Empty(t, trimEKSClusterName(vals))

	vals = "invalid-arn-format"
	assert.Equal(t, "invalid-arn-format", trimEKSClusterName(vals))

	vals = "arn:aws:eks:region:account-id:cluster/"
	assert.Empty(t, trimEKSClusterName(vals))

	vals = "arn:aws:eks:eu-west-1:111111111111:cluster/my-cluster"
	assert.Equal(t, "my-cluster", trimEKSClusterName(vals))

	vals = "arn:aws:eks:us-west-1:123456789012:cluster/eks-my-cluster"
	assert.Equal(t, "eks-my-cluster", trimEKSClusterName(vals))

	vals = "my-cluster.eu-west-1.eksctl.io"
	assert.Equal(t, "my-cluster", trimEKSClusterName(vals))

	vals = "eks-cilium-test-1.ap-northeast-1.eksctl.io"
	assert.Equal(t, "eks-cilium-test-1", trimEKSClusterName(vals))
}

type fakeInstallerClient struct {
	*k8s.Client
	apiServerHost string
	apiServerPort string
}

func (f fakeInstallerClient) ListNodes(context.Context, metav1.ListOptions) (*corev1.NodeList, error) {
	return &corev1.NodeList{}, nil
}

func (f fakeInstallerClient) ListDaemonSet(context.Context, string, metav1.ListOptions) (*appsv1.DaemonSetList, error) {
	return &appsv1.DaemonSetList{}, nil
}

func (f fakeInstallerClient) GetDaemonSet(context.Context, string, string, metav1.GetOptions) (*appsv1.DaemonSet, error) {
	return nil, nil
}

func (f fakeInstallerClient) PatchDaemonSet(context.Context, string, string, types.PatchType, []byte, metav1.PatchOptions) (*appsv1.DaemonSet, error) {
	return nil, nil
}

func (f fakeInstallerClient) GetEndpointSlice(context.Context, string, string, metav1.GetOptions) (*discoveryv1.EndpointSlice, error) {
	return nil, nil
}

func (f fakeInstallerClient) GetAPIServerHostAndPort() (string, string) {
	return f.apiServerHost, f.apiServerPort
}

func (f fakeInstallerClient) AutodetectFlavor(context.Context) k8s.Flavor {
	return k8s.Flavor{}
}

func (f fakeInstallerClient) GetNamespace(context.Context, string, metav1.GetOptions) (*corev1.Namespace, error) {
	return nil, nil
}

func (f fakeInstallerClient) DeleteNamespace(context.Context, string, metav1.DeleteOptions) error {
	return nil
}

func (f fakeInstallerClient) DeletePodCollection(context.Context, string, metav1.DeleteOptions, metav1.ListOptions) error {
	return nil
}

func (f fakeInstallerClient) PatchNode(context.Context, string, types.PatchType, []byte) (*corev1.Node, error) {
	return nil, nil
}

func TestAutodetectKubeProxyUsesAPIServerPortFromKubeconfig(t *testing.T) {
	installer := &K8sInstaller{
		client: fakeInstallerClient{
			Client:        &k8s.Client{},
			apiServerHost: "api.example.test",
			apiServerPort: "443",
		},
		params: Parameters{Writer: io.Discard},
		flavor: k8s.Flavor{},
	}

	err := installer.autodetectKubeProxy(context.Background(), map[string]any{})
	assert.NoError(t, err)
	assert.Contains(t, installer.params.HelmOpts.Values, "kubeProxyReplacement=true")
	assert.Contains(t, installer.params.HelmOpts.Values, "k8sServiceHost=api.example.test")
	assert.Contains(t, installer.params.HelmOpts.Values, "k8sServicePort=443")
}
