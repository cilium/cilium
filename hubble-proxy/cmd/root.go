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
	"github.com/cilium/cilium/hubble-proxy/cmd/completion"
	"github.com/cilium/cilium/hubble-proxy/cmd/version"
	v "github.com/cilium/cilium/pkg/version"

	"github.com/spf13/cobra"
)

// New creates a new hubble-proxy command.
func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "hubble-proxy",
		Short:        "hubble-proxy is a proxy server for the hubble API",
		Long:         "hubble-proxy is a proxy server for the hubble API.",
		SilenceUsage: true,
		Version:      v.GetCiliumVersion().Version,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Root().Usage()
		},
	}
	rootCmd.AddCommand(
		completion.New(),
		version.New(),
	)
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")
	return rootCmd
}
