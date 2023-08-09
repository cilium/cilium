package clustermesh

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/release"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium-cli/k8s"
)

func TestNeedClassicMode(t *testing.T) {
	uu := map[string]struct {
		r   release.Release
		err error
		e   bool
	}{
		"blank": {
			r: release.Release{
				Chart: &chart.Chart{},
			},
			err: errors.New(`failed to parse Cilium version: strconv.ParseUint: parsing "": invalid syntax`),
		},
		"1.13.1": {
			r: release.Release{
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{AppVersion: "1.13.1"},
				},
			},
			e: true,
		},
		"v1.13.1": {
			r: release.Release{
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{AppVersion: "v1.13.1"},
				},
			},
			e: true,
		},
		"v1.13.1-pre.2": {
			r: release.Release{
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{AppVersion: "v1.13.1-pre.2"},
				},
			},
			e: true,
		},
		"v1.14.0": {
			r: release.Release{
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{AppVersion: "v1.14.0"},
				},
			},
		},
		"v1.14.0-snapshot.2": {
			r: release.Release{
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{AppVersion: "v1.14.0-snapshot.2"},
				},
			},
		},
		"v1.14.10": {
			r: release.Release{
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{AppVersion: "v1.14.10"},
				},
			},
		},
	}

	c := K8sClusterMesh{
		params: Parameters{Writer: noOptWriter{}},
	}
	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			ok, err := c.needsClassicMode(&u.r)
			if err != nil {
				assert.Equal(t, u.err.Error(), err.Error())
				return
			}
			assert.Equal(t, u.e, ok)
		})
	}
}

func TestRemoveFromClustermeshConfig(t *testing.T) {
	uu := map[string]struct {
		vv      map[string]any
		cluster string
		err     error
		e       map[string]any
	}{
		"missing": {
			cluster: "test1",
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
			cluster: "c2",
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
			cluster: "c2",
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
						}, "enabled": true},
				},
			},
		},
		"not-connected": {
			cluster: "c4",
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
			ee, err := removeFromClustermeshConfig(u.vv, u.cluster)
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

// Helpers

type noOptWriter struct{}

func (noOptWriter) Write([]byte) (int, error) { return 0, nil }
