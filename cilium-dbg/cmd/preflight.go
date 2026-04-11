// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/option"
)

// PreflightCmd is the command used to manage preflight tasks for upgrades
var PreflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Cilium upgrade helper",
	Long:  `CLI to help upgrade cilium`,
}

func init() {
	// From preflight_migrate_crd_identity.go
	miCmd := migrateIdentityCmd()
	miCmd.Flags().StringVar(&kvStore, "kvstore", "", "Key-value store type")
	miCmd.Flags().Var(option.NewMapOptions(&kvStoreOpts), "kvstore-opt", "Key-value store options e.g. etcd.address=127.0.0.1:4001")
	PreflightCmd.AddCommand(miCmd)

	PreflightCmd.AddCommand(validateCNPCmd())

	RootCmd.AddCommand(PreflightCmd)

	PreflightCmd.AddCommand(validateConfigmapCmd())

}
