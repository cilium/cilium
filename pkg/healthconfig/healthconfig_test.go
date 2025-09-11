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

	"github.com/cilium/cilium/pkg/time"
)

func Test_healthConfig(t *testing.T) {
	var hc CiliumHealthConfig
	hive := hive.New(
		Cell,
		cell.Invoke(func(cfg CiliumHealthConfig) { hc = cfg }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)
	flags.Set("enable-health-checking", "true")
	flags.Set("enable-endpoint-health-checking", "true")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	require.NoError(t, hive.Start(tlog, ctx))

	require.True(t, hc.IsHealthCheckingEnabled())
	require.True(t, hc.IsEndpointHealthCheckingEnabled())
}
