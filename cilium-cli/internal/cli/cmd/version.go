// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/defaults"
)

// The following variables are set at compile time via LDFLAGS.
var (
	// Version is the software version.
	Version string
)

func getLatestStableVersion() string {
	resp, err := http.Get("https://raw.githubusercontent.com/cilium/cilium/main/stable.txt")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}

	return strings.TrimSpace(string(b))
}

func newCmdVersion() *cobra.Command {
	var clientOnly bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display detailed version information",
		Long:  `Displays information about the version of this software.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("cilium-cli: %s compiled with %v on %v/%v\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			fmt.Printf("cilium image (default): %s\n", defaults.Version)
			fmt.Printf("cilium image (stable): %s\n", getLatestStableVersion())
			if clientOnly {
				return nil
			}
			version, err := k8sClient.GetRunningCiliumVersion(context.Background(), namespace)
			if version == "" || err != nil {
				fmt.Printf("cilium image (running): unknown. Unable to obtain cilium version, no cilium pods found in namespace %q\n", namespace)
			} else {
				fmt.Printf("cilium image (running): %s\n", version)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&clientOnly, "client", false, "If true, shows client version only (no server required)")
	return cmd
}
