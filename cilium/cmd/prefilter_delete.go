// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
)

var preFilterDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete CIDR filters",
	Run: func(cmd *cobra.Command, args []string) {
		deleteFilters(cmd, args)
	},
}

func init() {
	preFilterCmd.AddCommand(preFilterDeleteCmd)
	preFilterDeleteCmd.Flags().Uint64VarP(&revision, "revision", "", 0, "Update revision")
	preFilterDeleteCmd.Flags().StringSliceVarP(&cidrs, "cidr", "", []string{}, "List of CIDR prefixes to delete")
}

func deleteFilters(cmd *cobra.Command, args []string) {
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
	if _, err := client.DeletePrefilter(spec); err != nil {
		Fatalf("Cannot delete prefilter: %s", err)
	} else {
		fmt.Printf("Deleted %d prefilter entries\n", len(spec.Deny))
	}
}
