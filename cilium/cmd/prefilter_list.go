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
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var preFilterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List CIDR filters",
	Run: func(cmd *cobra.Command, args []string) {
		listFilters(cmd, args)
	},
}

func init() {
	preFilterCmd.AddCommand(preFilterListCmd)
	AddMultipleOutput(preFilterListCmd)
}

func listFilters(cmd *cobra.Command, args []string) {
	var str string
	cl, err := client.GetPrefilter()
	if err != nil {
		Fatalf("Cannot get CIDR list: %s", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	str = fmt.Sprintf("Revision: %d", cl.Revision)
	fmt.Fprintln(w, str)
	for _, pfx := range cl.List {
		str = fmt.Sprintf("%s", pfx)
		fmt.Fprintln(w, str)
	}
	w.Flush()
}
