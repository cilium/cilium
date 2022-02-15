// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
)

var (
	revision uint64
	cidrs    []string
)

var preFilterUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update CIDR filters",
	Run: func(cmd *cobra.Command, args []string) {
		updateFilters(cmd, args)
	},
}

func init() {
	preFilterCmd.AddCommand(preFilterUpdateCmd)
	preFilterUpdateCmd.Flags().Uint64VarP(&revision, "revision", "", 0, "Update revision")
	preFilterUpdateCmd.Flags().StringSliceVarP(&cidrs, "cidr", "", []string{}, "List of CIDR prefixes to block")
}

func updateFilters(cmd *cobra.Command, args []string) {
	spec := &models.PrefilterSpec{
		Revision: int64(revision),
		Deny:     cidrs,
	}
	for _, cidr := range cidrs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			Fatalf("Cannot parse CIDR \"%s\": %s", cidr, err)
		}
	}
	if _, err := client.PatchPrefilter(spec); err != nil {
		Fatalf("Cannot add/update prefilter: %s", err)
	} else {
		fmt.Printf("Updated %d prefilter entries\n", len(spec.Deny))
	}
}
