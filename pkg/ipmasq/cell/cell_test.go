// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	ipmasqmaps "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// newTestHive builds a hive holding the ip-masq-agent module and nothing that
// consumes it: the agent must be started by the module's own invoke.
func newTestHive(t *testing.T, enabled bool, configPath string) *hive.Hive {
	t.Helper()

	h := hive.New(
		// Needed for the metrics.Cell
		cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
		// Needed for the IPMasqBPFMap
		metrics.Cell,
		ipmasqmaps.Cell,
		Cell,
	)

	hive.AddConfigOverride(h, func(cfg *Config) {
		cfg.EnableIPMasqAgent = enabled
		cfg.IPMasqAgentConfigPath = configPath
	})

	return h
}

func TestIPMasqAgentCell(t *testing.T) {
	h := newTestHive(t, true, path.Join(t.TempDir(), "placeholder.yaml"))

	ctx := context.Background()
	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))
	require.NoError(t, h.Stop(tlog, ctx))
}

// TestIPMasqAgentCellStartsAgent asserts that the agent is constructed and
// started even though nothing in the hive depends on it. It points the agent
// at a config file whose directory does not exist, which makes the fsnotify
// watcher, and therefore the start hook, fail: an agent that was never
// constructed would let the hive start cleanly instead.
func TestIPMasqAgentCellStartsAgent(t *testing.T) {
	h := newTestHive(t, true, path.Join(t.TempDir(), "missing", "placeholder.yaml"))

	err := h.Start(hivetest.Logger(t), context.Background())
	require.ErrorContains(t, err, "failed to start ip-masq-agent")
}

// TestIPMasqAgentCellDisabled is the counterpart of
// TestIPMasqAgentCellStartsAgent: with the same unusable config path, the hive
// starts cleanly because no agent is registered at all.
func TestIPMasqAgentCellDisabled(t *testing.T) {
	h := newTestHive(t, false, path.Join(t.TempDir(), "missing", "placeholder.yaml"))

	ctx := context.Background()
	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))
	require.NoError(t, h.Stop(tlog, ctx))
}
