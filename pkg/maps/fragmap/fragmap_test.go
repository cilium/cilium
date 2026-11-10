// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedFragmentMapsHive(t *testing.T) {
	testutils.PrivilegedTest(t)

	tests := []struct {
		name       string
		enableIPv4 bool
		enableIPv6 bool
	}{
		{"ipv4-and-ipv6", true, true},
		{"ipv4-only", true, false},
		{"ipv6-only", false, true},
		{"disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			type in struct {
				cell.In

				Map Map
			}

			daemonConfig := option.DaemonConfig{
				EnableIPv4FragmentsTracking: tt.enableIPv4,
				EnableIPv6FragmentsTracking: tt.enableIPv6,
				FragmentsMapEntries:         1234,
			}
			h := hive.New(
				registry.Cell,
				metrics.Cell,
				Cell,
				cell.Provide(func() *option.DaemonConfig { return &daemonConfig }),
				cell.Invoke(func(in in) {
					require.NotNil(t, in.Map)
				}),
			)

			ctx := context.Background()
			logger := hivetest.Logger(t)
			require.NoError(t, h.Start(logger, ctx))
			t.Cleanup(func() {
				require.NoError(t, h.Stop(logger, ctx))
			})

			for _, mapConfig := range []struct {
				name    string
				enabled bool
				open    func() (*bpf.Map, error)
			}{
				{mapNameIPv4, tt.enableIPv4, func() (*bpf.Map, error) { return OpenMap4(logger) }},
				{mapNameIPv6, tt.enableIPv6, func() (*bpf.Map, error) { return OpenMap6(logger) }},
			} {
				path := bpf.MapPath(logger, mapConfig.name)
				if !mapConfig.enabled {
					require.NoFileExists(t, path)
					continue
				}

				require.FileExists(t, path)
				m, err := mapConfig.open()
				require.NoError(t, err)
				require.Equal(t, uint32(daemonConfig.FragmentsMapEntries), m.MaxEntries())
				t.Cleanup(func() {
					require.NoError(t, m.Unpin())
					require.NoError(t, m.Close())
				})
			}
		})
	}
}
