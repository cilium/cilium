// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipmasq"
	ipmasqmaps "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func TestIPMasqAgentCell(t *testing.T) {
	testutils.PrivilegedTest(t)

	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		// Needed for the metrics.Cell
		cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
		// Needed for the IPMasqBPFMap
		metrics.Cell,
		ipmasqmaps.Cell,
		Cell,
		cell.Invoke(func(a *ipmasq.IPMasqAgent) {
			agent = a
		}),
	)

	configFile, err := os.CreateTemp("", "ipmasq-test")
	require.NoError(t, err)

	hive.AddConfigOverride(testHive, func(cfg *Config) {
		cfg.EnableIPMasqAgent = true
		cfg.IPMasqAgentConfigPath = configFile.Name()
	})

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err = testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Verify that the agent was successfully created
	assert.NotNil(t, agent)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
	err = os.Remove(configFile.Name())
	require.NoError(t, err)
}

func TestIPMasqAgentCellDisabled(t *testing.T) {
	testutils.PrivilegedTest(t)

	var agent *ipmasq.IPMasqAgent

	testHive := hive.New(
		// Needed for the metrics.Cell
		cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
		// Needed for the IPMasqBPFMap
		metrics.Cell,
		ipmasqmaps.Cell,
		Cell,
		cell.Invoke(func(a *ipmasq.IPMasqAgent) {
			agent = a
		}),
	)

	// Disable via config
	hive.AddConfigOverride(testHive, func(cfg *Config) {
		cfg.EnableIPMasqAgent = false
	})

	// Start the hive
	ctx := context.Background()
	tlog := hivetest.Logger(t)
	err := testHive.Start(tlog, ctx)
	require.NoError(t, err)

	// Verify that the agent was not created
	assert.Nil(t, agent)

	// Stop the hive
	err = testHive.Stop(tlog, ctx)
	require.NoError(t, err)
}
