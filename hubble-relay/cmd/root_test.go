// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hubble/relay/server"
)

// testServeExtension verifies that root-command options reach the serve command.
type testServeExtension struct{}

// Name implements the serve.Extension interface.
func (testServeExtension) Name() string {
	return "test"
}

// RegisterFlags implements the serve.Extension interface. It adds a
// recognizable flag for the root-command propagation test.
func (testServeExtension) RegisterFlags(flags *pflag.FlagSet) {
	flags.Bool("downstream-feature", false, "enable a downstream feature")
}

// Configure implements the serve.Extension interface without changing the
// Relay server.
func (testServeExtension) Configure(context.Context, *slog.Logger, *viper.Viper) ([]server.Option, io.Closer, error) {
	return nil, nil, nil
}

func TestWithServeExtensions(t *testing.T) {
	root := New(WithServeExtensions(testServeExtension{}))
	serveCmd, _, err := root.Find([]string{"serve"})
	require.NoError(t, err)
	require.NotNil(t, serveCmd)

	flag := serveCmd.Flags().Lookup("downstream-feature")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}
