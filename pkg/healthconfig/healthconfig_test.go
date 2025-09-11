// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthconfig

import (
	"context"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func Test_healthConfig(t *testing.T) {
	var hc CiliumHealthConfig
	hive := hive.New(
		Cell,
		cell.Invoke(func(cfg CiliumHealthConfig) { hc = cfg }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)
	flags.Set(EnableHealthCheckingName, "false")
	flags.Set(EnableEndpointHealthCheckingName, "false")

	tlog := hivetest.Logger(t)
	require.NoError(t, hive.Start(tlog, context.Background()))

	require.False(t, hc.IsHealthCheckingEnabled())
	require.False(t, hc.IsEndpointHealthCheckingEnabled())
}
