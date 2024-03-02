// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/defaults"
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
		Use:   "Version",
		Short: "Display detailed Version information",
		Long:  `Displays information about the Version of this software.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("cilium-cli: %s compiled with %v on %v/%v\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			fmt.Printf("cilium image (default): %s\n", defaults.Version)
			fmt.Printf("cilium image (stable): %s\n", getLatestStableVersion())
			if clientOnly {
				return nil
			}
			version, err := K8sClient.GetRunningCiliumVersion()
			if err != nil {
				fmt.Printf("cilium image (running): unknown. Unable to obtain cilium Version. Reason: %s\n", err.Error())
			} else {
				fmt.Printf("cilium image (running): %s\n", version)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&clientOnly, "client", false, "If true, shows client Version only (no server required)")
	return cmd
}
