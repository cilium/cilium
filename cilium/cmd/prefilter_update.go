// Copyright 2017 Authors of Cilium
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
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/spf13/cobra"
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
