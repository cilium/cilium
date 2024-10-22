// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/observe"
	"github.com/cilium/cilium/hubble/pkg/defaults"
)

//go:embed observe_help.txt
var expectedObserveHelp string

func init() {
	// Override the client so that it always returns an IOReaderObserver with no flows.
	observe.GetHubbleClientFunc = func(_ context.Context, _ *viper.Viper) (client observerpb.ObserverClient, cleanup func() error, err error) {
		cleanup = func() error { return nil }
		return observe.NewIOReaderObserver(new(bytes.Buffer)), cleanup, nil
	}

	expectedObserveHelp = fmt.Sprintf(expectedObserveHelp, defaults.ConfigFile)
}

var observeRawFilterArgs = []string{"--allowlist", `{"source_pod":["kube-system/"]}`, "--denylist", `{"source_ip":["1.1.1.1"]}`, "--print-raw-filters"}
var observeRawFilterOut = `allowlist:
    - '{"source_pod":["kube-system/"]}'
denylist:
    - '{"source_ip":["1.1.1.1"]}'
`

func TestTestHubbleObserve(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectErr      error
		expectedOutput string
	}{
		{
			name: "observe no flags",
			args: []string{"observe"},
		},
		{
			name: "observe formatting flags",
			args: []string{"observe", "-o", "json"},
		},
		{
			name: "observe server flags",
			args: []string{"observe", "--server", "foo.example.org", "--tls", "--tls-allow-insecure"},
		},
		{
			name: "observe filter flags",
			args: []string{"observe", "--from-pod", "foo/test-pod-1234", "--type", "l7"},
		},
		{
			name: "help",
			args: []string{"--help"},
			expectedOutput: fmt.Sprintf(`Hubble is a utility to observe and inspect recent Cilium routed traffic in a cluster.

Usage:
  hubble [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  config      Modify or view hubble config
  help        Help about any command
  list        List Hubble objects
  observe     Observe flows and events of a Hubble server
  status      Display status of Hubble server
  version     Display detailed version information

Global Flags:
      --config string   Optional config file (default "%s")
  -D, --debug           Enable debug messages

Get help:
  -h, --help	Help for any command or subcommand

Use "hubble [command] --help" for more information about a command.
`, defaults.ConfigFile),
		},
		{
			name:           "observe help",
			args:           []string{"observe", "--help"},
			expectedOutput: expectedObserveHelp,
		},
		{
			name:           "observe raw filters",
			args:           append([]string{"observe"}, observeRawFilterArgs...),
			expectedOutput: observeRawFilterOut,
		},
		{
			name:           "observe flows raw filters",
			args:           append([]string{"observe", "flows"}, observeRawFilterArgs...),
			expectedOutput: observeRawFilterOut,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			cli := New()
			cli.SetOut(&b)
			cli.SetArgs(tt.args)
			err := cli.Execute()
			require.Equal(t, tt.expectErr, err)
			output := b.String()
			if tt.expectedOutput != "" {
				assert.Equal(t, tt.expectedOutput, output, "expected output does not match")
			}
		})
	}
}
