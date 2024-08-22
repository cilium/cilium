// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

// Helper function to compare two slices of maps ignoring the order
func equalClusterSlices(a, b []map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}

	bCopy := make([]map[string]interface{}, len(b))
	copy(bCopy, b)

	return slices.EqualFunc(a, bCopy, func(m1, m2 map[string]interface{}) bool {
		for i, bm := range bCopy {
			if reflect.DeepEqual(m1, bm) {
				bCopy = append(bCopy[:i], bCopy[i+1:]...)
				return true
			}
		}
		return false
	})
}

func TestMergeClusters(t *testing.T) {
	uu := map[string]struct {
		oc            []map[string]interface{}
		nc            []map[string]interface{}
		exceptCluster string
		err           error
		e             map[string]interface{}
	}{
		"nil-new-one": {
			oc: []map[string]interface{}{},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
			},
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
						},
					},
				},
			},
		},
		"nil-new-some": {
			oc: []map[string]interface{}{},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.7"},
					"name": "c2",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.8"},
					"name": "c1",
					"port": "32379",
				},
			},
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.7"},
								"name": "c2",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.8"},
								"name": "c1",
								"port": "32379",
							},
						},
					},
				},
			},
		},
		"oc-new-some": {
			oc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.5"},
					"name": "c2",
					"port": "32379"},
				{
					"ips":  []string{"172.19.0.4"},
					"name": "c1",
					"port": "32379"},
			},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.7"},
					"name": "c4",
					"port": "32379",
				},
			},
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.5"},
								"name": "c2",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.7"},
								"name": "c4",
								"port": "32379",
							},
						},
					},
				},
			},
		},
		"already-there": {
			oc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.5"},
					"name": "c2",
					"port": "32379"},
				{
					"ips":  []string{"172.19.0.4"},
					"name": "c1",
					"port": "32379"},
			},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
			},
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.5"},
								"name": "c2",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
						},
					},
				},
			},
		},
		"already-there-partially": {
			oc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.5"},
					"name": "c2",
					"port": "32379"},
				{
					"ips":  []string{"172.19.0.4"},
					"name": "c1",
					"port": "32379"},
			},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.7"},
					"name": "c4",
					"port": "32379",
				},
			},
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.5"},
								"name": "c2",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.7"},
								"name": "c4",
								"port": "32379"},
						},
					},
				},
			},
		},
		"except-nc-changed": {
			oc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.5"},
					"name": "c2",
					"port": "32379"},
				{
					"ips":  []string{"172.19.0.4"},
					"name": "c1",
					"port": "32379"},
			},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.8"},
					"name": "c5",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.7"},
					"name": "c4",
					"port": "32379",
				},
			},
			exceptCluster: "c4",
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.5"},
								"name": "c2",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.8"},
								"name": "c5",
								"port": "32379"},
						},
					},
				},
			},
		},
		"except-nc-same": {
			oc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.5"},
					"name": "c2",
					"port": "32379"},
				{
					"ips":  []string{"172.19.0.4"},
					"name": "c1",
					"port": "32379"},
			},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.7"},
					"name": "c4",
					"port": "32379",
				},
			},
			exceptCluster: "c4",
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.5"},
								"name": "c2",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
						},
					},
				},
			},
		},
		"except-oc": {
			oc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.5"},
					"name": "c2",
					"port": "32379"},
				{
					"ips":  []string{"172.19.0.4"},
					"name": "c1",
					"port": "32379"},
			},
			nc: []map[string]interface{}{
				{
					"ips":  []string{"172.19.0.6"},
					"name": "c3",
					"port": "32379",
				},
				{
					"ips":  []string{"172.19.0.7"},
					"name": "c4",
					"port": "32379",
				},
			},
			exceptCluster: "c2",
			e: map[string]interface{}{
				"clustermesh": map[string]interface{}{
					"config": map[string]interface{}{
						"enabled": true,
						"clusters": []map[string]interface{}{
							{
								"ips":  []string{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []string{"172.19.0.5"},
								"name": "c2",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
							{
								"ips":  []string{"172.19.0.7"},
								"name": "c4",
								"port": "32379"},
						},
					},
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

			// Compare the clusters ignoring the order
			expectedClusters := u.e["clustermesh"].(map[string]interface{})["config"].(map[string]interface{})["clusters"].([]map[string]interface{})
			actualClusters := ee["clustermesh"].(map[string]interface{})["config"].(map[string]interface{})["clusters"].([]map[string]interface{})

			assert.True(t, equalClusterSlices(expectedClusters, actualClusters))
		})
	}
}

func TestRemoveFromClustermeshConfig(t *testing.T) {
	uu := map[string]struct {
		vv       map[string]any
		clusters []string
		err      error
		e        map[string]any
	}{
		"missing": {
			clusters: []string{"test1", "test2"},
			e: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []map[string]any{},
						"enabled":  true,
					},
				},
			},
		},
		"empty": {
			clusters: []string{"c1", "c2"},
			vv: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": nil,
					},
				},
			},
			e: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []map[string]any{},
						"enabled":  true,
					},
				},
			},
		},
		"connected": {
			clusters: []string{"c1", "c2"},
			vv: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []any{
							map[string]any{
								"ips":  []any{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							map[string]any{
								"ips":  []any{"172.19.0.4"},
								"name": "c2",
								"port": "32379"},
							map[string]any{
								"ips":  []any{"172.19.0.4"},
								"name": "c1",
								"port": "32379"},
						},
					},
				},
			},
			e: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []map[string]any{
							{
								"ips":  []any{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
						}, "enabled": true},
				},
			},
		},
		"partially-connected": {
			clusters: []string{"c3", "c4"},
			vv: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []any{
							map[string]any{
								"ips":  []any{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							map[string]any{
								"ips":  []any{"172.19.0.4"},
								"name": "c2",
								"port": "32379"},
						},
					},
				},
			},
			e: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []map[string]any{
							{
								"ips":  []any{"172.19.0.4"},
								"name": "c2",
								"port": "32379",
							},
						}, "enabled": true},
				},
			},
		},
		"not-connected": {
			clusters: []string{"c1", "c4"},
			vv: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []any{
							map[string]any{
								"ips":  []any{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							map[string]any{
								"ips":  []any{"172.19.0.4"},
								"name": "c2",
								"port": "32379"},
						},
					},
				},
			},
			e: map[string]any{
				"clustermesh": map[string]any{
					"config": map[string]any{
						"clusters": []map[string]any{
							{
								"ips":  []any{"172.19.0.6"},
								"name": "c3",
								"port": "32379",
							},
							{
								"ips":  []any{"172.19.0.4"},
								"name": "c2",
								"port": "32379",
							},
						},
						"enabled": true,
					},
				},
			},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			ee, err := removeFromClustermeshConfig(u.vv, u.clusters)
			if err != nil {
				assert.Equal(t, u.err, err)
				return
			}
			assert.Equal(t, u.e, ee)
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
				Connected: true, Config: &models.RemoteClusterConfig{Required: true}},
			expected: "remote cluster configuration required but not found",
		},
		{
			name: "connected, config not required, sync status unknown",
			status: &models.RemoteCluster{
				Connected: true, Config: &models.RemoteClusterConfig{}},
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
