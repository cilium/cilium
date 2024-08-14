// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// EnvoyAdminCmd represents the Envoy Proxy admin interface command
var EnvoyAdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Access Envoy Admin Interface",
}

func init() {
	EnvoyCmd.AddCommand(EnvoyAdminCmd)
}
