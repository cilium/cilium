// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/release/common"
	v1release "helm.sh/helm/v4/pkg/release/v1"
	"helm.sh/helm/v4/pkg/storage"
	"helm.sh/helm/v4/pkg/storage/driver"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMaxHistory(t *testing.T) {
	assert := assert.New(t)

	p := Parameters{
		Version:        "1.16.4",
		HelmMaxHistory: 15,
	}

	installer, err := NewK8sInstaller(nil, p)
	assert.NoError(err)
	assert.Equal(15, installer.params.HelmMaxHistory)
}

type fakeKubeProxyClient struct {
	k8sInstallerImplementation
}

func (f *fakeKubeProxyClient) ListDaemonSet(context.Context, string, metav1.ListOptions) (*appsv1.DaemonSetList, error) {
	return &appsv1.DaemonSetList{}, nil
}

func (f *fakeKubeProxyClient) GetAPIServerHostAndPort() (string, string) {
	return "localhost", "11792"
}

func TestUpgradeAutodetectKubeProxyReusedValues(t *testing.T) {
	actionConfig := &action.Configuration{Releases: storage.Init(driver.NewMemory())}
	require.NoError(t, actionConfig.Releases.Create(&v1release.Release{
		Name:      "cilium",
		Namespace: "kube-system",
		Version:   1,
		Info:      &v1release.Info{Status: common.StatusDeployed},
		Config: map[string]any{
			"kubeProxyReplacement": true,
			"k8sServiceHost":       "172.18.0.2",
			"k8sServicePort":       8443,
		},
	}))

	for _, tt := range []struct {
		name     string
		params   Parameters
		expected []string
	}{
		{
			name:     "reuse-values",
			params:   Parameters{HelmReuseValues: true},
			expected: []string{"encryption.enabled=true"},
		},
		{
			name:     "reset-then-reuse-values",
			params:   Parameters{HelmResetThenReuseValues: true},
			expected: []string{"encryption.enabled=true"},
		},
		{
			name:   "reset-values",
			params: Parameters{HelmResetValues: true, HelmReuseValues: true},
			expected: []string{"encryption.enabled=true", "kubeProxyReplacement=true",
				"k8sServiceHost=localhost", "k8sServicePort=11792"},
		},
		{
			name:   "no reuse",
			params: Parameters{},
			expected: []string{"encryption.enabled=true", "kubeProxyReplacement=true",
				"k8sServiceHost=localhost", "k8sServicePort=11792"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.params.HelmReleaseName = "cilium"
			tt.params.Writer = io.Discard
			tt.params.HelmOpts = values.Options{Values: []string{"encryption.enabled=true"}}
			k := &K8sInstaller{client: &fakeKubeProxyClient{}, params: tt.params}

			releaseValues, err := k.reusedReleaseValues(actionConfig)
			require.NoError(t, err)
			helmValues, err := k.autodetectionValues(releaseValues)
			require.NoError(t, err)
			require.NoError(t, k.autodetectKubeProxy(context.Background(), helmValues))
			assert.Equal(t, tt.expected, k.params.HelmOpts.Values)
		})
	}
}
