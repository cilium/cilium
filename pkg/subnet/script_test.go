// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	setup := func(t testing.TB, args []string) *script.Engine {
		h := hive.New(
			k8sClient.FakeClientCell(),

			dynamicconfig.Cell,
			cell.Provide(
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						RoutingMode: option.RoutingModeHybrid,
					}
				},
				regeneration.NewFence,
			),
			subnet.Cell,
			Cell,
			metrics.Cell,
		)
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args), "parse args")

		log := hivetest.Logger(t)

		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})
		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    1 * time.Second,
			MaxRetryInterval: 30 * time.Second, // For bpf map pressure metrics which run every 30s.
		}
	}

	scripttest.Test(t,
		t.Context(),
		setup,
		[]string{},
		"testdata/*.txtar")
}
