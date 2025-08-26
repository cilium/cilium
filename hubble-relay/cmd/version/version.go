// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package version

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/version"
)

// New creates a new version command.
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display detailed version information",
		Long:  `Displays information about the version of this software.`,
		Run: func(cmd *cobra.Command, _ []string) {
			runVersion(cmd.OutOrStdout())
		},
	}
}

func runVersion(out io.Writer) {
	fmt.Fprintf(out, "Hubble-relay: %s\n", version.Version)
}
