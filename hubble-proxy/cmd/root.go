// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"

	"github.com/cilium/cilium/hubble-proxy/cmd/completion"
	cmdContext "github.com/cilium/cilium/hubble-proxy/cmd/context"
	"github.com/cilium/cilium/hubble-proxy/cmd/version"
	"github.com/cilium/cilium/pkg/hubble/proxy"

	"github.com/spf13/cobra"
)

var cctx = cmdContext.New()

// New creates a new hubble-proxy command.
func New() *cobra.Command {
	if err := cctx.VP.ReadInConfig(); err != nil {
		// config file is entirely optional
		cctx.Log.WithError(err).Debug("loading configuration file skipped")
	}

	ctx := context.Background()
	rootCmd := &cobra.Command{
		Use:          "hubble-proxy",
		Short:        "hubble-proxy is a proxy server for the hubble API",
		Long:         "hubble-proxy is a proxy server for the hubble API.",
		SilenceUsage: true,
		Version:      proxy.Version,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Root().Usage()
		},
	}
	rootCmd.AddCommand(
		completion.New(ctx, cctx),
		version.New(ctx, cctx),
	)
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"%s\" .Version}}\n")
	return rootCmd
}
