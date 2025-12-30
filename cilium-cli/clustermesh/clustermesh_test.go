// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/release"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

func TestMergeClusters(t *testing.T) {
	uu := map[string]struct {
		oc            map[string]any
		nc            map[string]any
		exceptCluster string
		err           error
		e             map[string]any
	}{
		"nil-new-one": {
			oc: map[string]any{},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
			},
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
			},
		},
		"nil-new-some": {
			oc: map[string]any{},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.8"},
					"port": "32379",
				},
			},
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.8"},
					"port": "32379",
				},
			},
		},
		"oc-new-some": {
			oc: map[string]any{
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
			e: map[string]any{
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
		},
		"already-there": {
			oc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
			},
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
		},
		"already-there-partially": {
			oc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
		},
		"except-nc-changed": {
			oc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
			nc: map[string]any{
				"c5": map[string]any{
					"ips":  []string{"172.19.0.8"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
			exceptCluster: "c4",
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
				"c5": map[string]any{
					"ips":  []string{"172.19.0.8"},
					"port": "32379",
				},
			},
		},
		"except-nc-same": {
			oc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
			exceptCluster: "c4",
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
		},
		"except-oc": {
			oc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
			},
			nc: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
			exceptCluster: "c2",
			e: map[string]any{
				"c3": map[string]any{
					"ips":  []string{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []string{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []string{"172.19.0.4"},
					"port": "32379",
				},
				"c4": map[string]any{
					"ips":  []string{"172.19.0.7"},
					"port": "32379",
				},
			},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			ee, err := mergeClusters(u.oc, u.nc, u.exceptCluster)
			if err != nil {
				assert.Equal(t, u.err, err)
				return
			}
			assert.Equal(t, u.e, ee)
		})
	}
}

func TestRemoveFromClustermeshConfig(t *testing.T) {
	tests := map[string]struct {
		values           map[string]any
		clusters         []string
		err              error
		expected         map[string]any
		expectedDisabled map[string]any
	}{
		"missing": {
			clusters:         []string{"test1", "test2"},
			expected:         map[string]any{},
			expectedDisabled: map[string]any{},
		},
		"empty": {
			clusters: []string{"c1", "c2"},
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": nil,
					},
				},
			},
			expected:         map[string]any{},
			expectedDisabled: map[string]any{},
		},
		"connected": {
			clusters: []string{"c1", "c2"},
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": map[string]any{
							"c3": map[string]any{
								"ips":  []any{"172.19.0.6"},
								"port": "32379",
							},
							"c2": map[string]any{
								"ips":  []any{"172.19.0.4"},
								"port": "32379",
							},
							"c1": map[string]any{
								"ips":  []any{"172.19.0.4"},
								"port": "32379",
							},
						},
					},
				},
			},
			expected: map[string]any{
				"c3": map[string]any{
					"ips":  []any{"172.19.0.6"},
					"port": "32379",
				},
			},
			expectedDisabled: map[string]any{},
		},
		"partially-connected": {
			clusters: []string{"c3", "c4"},
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": map[string]any{
							"c3": map[string]any{
								"ips":  []any{"172.19.0.6"},
								"port": "32379",
							},
							"c2": map[string]any{
								"ips":  []any{"172.19.0.4"},
								"port": "32379",
							},
						},
					},
				},
			},
			expected: map[string]any{
				"c2": map[string]any{
					"ips":  []any{"172.19.0.4"},
					"port": "32379",
				},
			},
			expectedDisabled: map[string]any{},
		},
		"not-connected": {
			clusters: []string{"c1", "c4"},
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": map[string]any{
							"c3": map[string]any{
								"ips":  []any{"172.19.0.6"},
								"port": "32379",
							},
							"c2": map[string]any{
								"ips":  []any{"172.19.0.4"},
								"port": "32379",
							},
						},
					},
				},
			},
			expected: map[string]any{
				"c3": map[string]any{
					"ips":  []any{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []any{"172.19.0.4"},
					"port": "32379",
				},
			},
			expectedDisabled: map[string]any{},
		},
		"disabled": {
			clusters: []string{"c1", "c4"},
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": map[string]any{
							"c5": map[string]any{
								"enabled": false,
								"ips":     []any{"172.19.0.8"},
								"port":    "32379",
							},
							"c4": map[string]any{
								"enabled": false,
								"ips":     []any{"172.19.0.7"},
								"port":    "32379",
							},
							"c3": map[string]any{
								"ips":  []any{"172.19.0.6"},
								"port": "32379",
							},
							"c2": map[string]any{
								"ips":  []any{"172.19.0.4"},
								"port": "32379",
							},
						},
					},
				},
			},
			expected: map[string]any{
				"c3": map[string]any{
					"ips":  []any{"172.19.0.6"},
					"port": "32379",
				},
				"c2": map[string]any{
					"ips":  []any{"172.19.0.4"},
					"port": "32379",
				},
			},
			expectedDisabled: map[string]any{
				"c5": map[string]any{
					"enabled": false,
					"ips":     []any{"172.19.0.8"},
					"port":    "32379",
				},
			},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			clusters, clustersDisabled, err := removeFromClustermeshConfig(test.values, test.clusters)
			if err != nil {
				assert.Equal(t, test.err, err)
				return
			}
			assert.Equal(t, test.expected, clusters)
			assert.Equal(t, test.expectedDisabled, clustersDisabled)
		})
	}
}

func TestRemoteClusterStatusToError(t *testing.T) {
	tests := []struct {
		name     string
		status   *models.RemoteCluster
		expected string
	}{
		{
			name:     "nil status",
			expected: "unknown status",
		},
		{
			name:     "not connected",
			status:   &models.RemoteCluster{Status: "foo"},
			expected: "foo",
		},
		{
			name:     "connected, unknown config",
			status:   &models.RemoteCluster{Connected: true},
			expected: "remote cluster configuration retrieval status unknown",
		},
		{
			name: "connected, config not found",
			status: &models.RemoteCluster{
				Connected: true, Config: &models.RemoteClusterConfig{Required: true},
			},
			expected: "remote cluster configuration required but not found",
		},
		{
			name: "connected, config not required, sync status unknown",
			status: &models.RemoteCluster{
				Connected: true, Config: &models.RemoteClusterConfig{},
			},
			expected: "synchronization status unknown",
		},
		{
			name: "connected, config found, no resource type synced",
			status: &models.RemoteCluster{
				Connected: true,
				Config:    &models.RemoteClusterConfig{Required: true, Retrieved: true},
				Synced:    &models.RemoteClusterSynced{},
			},
			expected: "synchronization in progress for endpoints, identities, nodes, services",
		},
		{
			name: "connected, config found, some resource type not synced",
			status: &models.RemoteCluster{
				Connected: true,
				Config:    &models.RemoteClusterConfig{Required: true, Retrieved: true},
				Synced:    &models.RemoteClusterSynced{Endpoints: true, Nodes: true, Services: true},
			},
			expected: "synchronization in progress for identities",
		},
		{
			name: "none of the above",
			status: &models.RemoteCluster{
				Connected: true,
				Config:    &models.RemoteClusterConfig{Required: true, Retrieved: true},
				Synced:    &models.RemoteClusterSynced{Endpoints: true, Identities: true, Nodes: true, Services: true},
			},
			expected: "not ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, remoteClusterStatusToError(tt.status).Error())
		})
	}
}

func TestGetCASecret(t *testing.T) {
	tests := []struct {
		name      string
		secret    *corev1.Secret
		expected  []byte
		assertErr assert.ErrorAssertionFunc
	}{
		{
			name:      "secret not present",
			secret:    k8s.NewSecret("bar", "foo", map[string][]byte{"ca.crt": []byte("cert")}),
			assertErr: assert.Error,
		},
		{
			name:      "secret present, ca.crt key",
			secret:    k8s.NewSecret("cilium-ca", "foo", map[string][]byte{"ca.crt": []byte("cert")}),
			expected:  []byte("cert"),
			assertErr: assert.NoError,
		},
		{
			name:      "secret present, tls.crt key",
			secret:    k8s.NewSecret("cilium-ca", "foo", map[string][]byte{"tls.crt": []byte("cert")}),
			expected:  []byte("cert"),
			assertErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := K8sClusterMesh{params: Parameters{Namespace: "foo"}}
			client := k8s.Client{Clientset: fake.NewSimpleClientset(tt.secret)}

			cert, err := cm.getCACert(context.TODO(), &client)
			assert.Equal(t, tt.expected, cert)
			tt.assertErr(t, err)
		})
	}
}

func TestGetClustersFromValues(t *testing.T) {
	tests := []struct {
		name                     string
		values                   map[string]any
		expected                 map[string]any
		expectedDisabledClusters map[string]any
		assertErr                assert.ErrorAssertionFunc
	}{
		{
			name:                     "null",
			values:                   nil,
			expected:                 map[string]any{},
			expectedDisabledClusters: map[string]any{},
			assertErr:                assert.NoError,
		},
		{
			name: "list",
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"enabled": true,
						"clusters": []any{
							map[string]any{
								"enabled": false,
								"ips":     []any{"172.19.0.7"},
								"name":    "c4",
								"port":    "32379",
							},
							map[string]any{
								"enabled": true,
								"ips":     []any{"172.19.0.6"},
								"name":    "c3",
								"port":    "32379",
							},
							map[string]any{
								"ips":  []any{"172.19.0.5"},
								"name": "c2",
								"port": "32379",
							},
							map[string]any{
								"ips":  []any{"172.19.0.4"},
								"name": "c1",
								"port": "32379",
							},
						},
					},
				},
			},
			expected: map[string]any{
				"c3": map[string]any{
					"enabled": true,
					"ips":     []any{"172.19.0.6"},
					"port":    "32379",
				},
				"c2": map[string]any{
					"ips":  []any{"172.19.0.5"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []any{"172.19.0.4"},
					"port": "32379",
				},
			},
			expectedDisabledClusters: map[string]any{
				"c4": map[string]any{
					"enabled": false,
					"ips":     []any{"172.19.0.7"},
					"port":    "32379",
				},
			},
			assertErr: assert.NoError,
		},
		{
			name: "map",
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"enabled": true,
						"clusters": map[string]any{
							"c4": map[string]any{
								"enabled": false,
								"ips":     []any{"172.19.0.7"},
								"port":    "32379",
							},
							"c3": map[string]any{
								"enabled": true,
								"ips":     []any{"172.19.0.6"},
								"port":    "32379",
							},
							"c2": map[string]any{
								"ips":  []any{"172.19.0.7"},
								"port": "32379",
							},
							"c1": map[string]any{
								"ips":  []any{"172.19.0.8"},
								"port": "32379",
							},
						},
					},
				},
			},
			expected: map[string]any{
				"c3": map[string]any{
					"enabled": true,
					"ips":     []any{"172.19.0.6"},
					"port":    "32379",
				},
				"c2": map[string]any{
					"ips":  []any{"172.19.0.7"},
					"port": "32379",
				},
				"c1": map[string]any{
					"ips":  []any{"172.19.0.8"},
					"port": "32379",
				},
			},
			expectedDisabledClusters: map[string]any{
				"c4": map[string]any{
					"enabled": false,
					"ips":     []any{"172.19.0.7"},
					"port":    "32379",
				},
			},
			assertErr: assert.NoError,
		},
		{
			name: "map-error-format",
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"enabled": true,
						"clusters": map[string]any{
							"c3": "test",
						},
					},
				},
			},
			expected:                 nil,
			expectedDisabledClusters: nil,
			assertErr:                assert.Error,
		},
		{
			name: "list-error-format",
			values: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"enabled":  true,
						"clusters": []any{"test"},
					},
				},
			},
			expected:                 nil,
			expectedDisabledClusters: nil,
			assertErr:                assert.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clusters, disabledClusters, err := getClustersFromValues(test.values)
			test.assertErr(t, err)
			assert.Equal(t, test.expected, clusters)
			assert.Equal(t, test.expectedDisabledClusters, disabledClusters)
		})
	}
}

func TestUpdateCABundleInValues(t *testing.T) {
	ca1 := "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----"
	ca2 := "-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----"

	tests := []struct {
		name            string
		releaseConfig   map[string]any
		clustersCA      map[string]string
		expectedContent string
		expectErr       bool
	}{
		{
			name: "empty clustersCA does not modify the bundle",
			releaseConfig: map[string]any{
				"tls": map[string]any{
					"caBundle": map[string]any{
						"enabled": true,
						"content": ca1,
					},
				},
			},
			clustersCA:      map[string]string{},
			expectedContent: ca1,
		},
		{
			name:            "add CA to empty bundle",
			releaseConfig:   map[string]any{},
			clustersCA:      map[string]string{"c2": ca2},
			expectedContent: ca2,
		},
		{
			name: "add CA to existing bundle",
			releaseConfig: map[string]any{
				"tls": map[string]any{
					"caBundle": map[string]any{
						"enabled": true,
						"content": ca1,
					},
				},
			},
			clustersCA:      map[string]string{"c2": ca2},
			expectedContent: ca1 + "\n" + ca2,
		},
		{
			name: "CA already in bundle",
			releaseConfig: map[string]any{
				"tls": map[string]any{
					"caBundle": map[string]any{
						"enabled": true,
						"content": ca1,
					},
				},
			},
			clustersCA:      map[string]string{"c1": ca1},
			expectedContent: ca1,
		},
		{
			name: "invalid caBundle content type",
			releaseConfig: map[string]any{
				"tls": map[string]any{
					"caBundle": map[string]any{"content": []any{"invalid"}},
				},
			},
			clustersCA: map[string]string{"c1": ca1},
			expectErr:  true,
		},
		{
			name: "invalid caBundle type",
			releaseConfig: map[string]any{
				"tls": map[string]any{"caBundle": "invalid"},
			},
			clustersCA: map[string]string{"c1": ca1},
			expectErr:  true,
		},
		{
			name:          "invalid tls type",
			releaseConfig: map[string]any{"tls": "invalid"},
			clustersCA:    map[string]string{"c1": ca1},
			expectErr:     true,
		},
		{
			name: "invalid ca bundle config (enabled but empty content)",
			releaseConfig: map[string]any{
				"tls": map[string]any{
					"caBundle": map[string]any{
						"enabled": true,
						"content": "",
					},
				},
			},
			clustersCA: map[string]string{"c1": ca1},
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel := &release.Release{Config: tt.releaseConfig}

			initialContent, _, _ := unstructured.NestedString(rel.Config, "tls", "caBundle", "content")

			err := updateCABundleInValues("cluster1", rel, tt.clustersCA)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			caBundleEnabled, _, err := unstructured.NestedBool(rel.Config, "tls", "caBundle", "enabled")
			assert.NoError(t, err)
			assert.True(t, caBundleEnabled)

			caBundleContent, _, err := unstructured.NestedString(rel.Config, "tls", "caBundle", "content")
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedContent, caBundleContent)

			if initialContent != tt.expectedContent {
				restartAnnotation, found, err := unstructured.NestedString(rel.Config, "clustermesh", "apiserver", "podAnnotations", "cilium.io/caBundleChangeRestartedAt")
				assert.NoError(t, err)
				assert.True(t, found, "restart annotation should be set")
				assert.NotEmpty(t, restartAnnotation, "restart annotation should have a value")
			}
		})
	}
}
