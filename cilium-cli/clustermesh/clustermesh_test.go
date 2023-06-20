package clustermesh

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
