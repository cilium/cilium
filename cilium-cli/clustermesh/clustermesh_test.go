package clustermesh

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/release"
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

// Helpers

type noOptWriter struct{}

func (noOptWriter) Write([]byte) (int, error) { return 0, nil }
