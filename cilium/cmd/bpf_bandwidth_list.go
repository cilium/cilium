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
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/bwmap"

	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/api/resource"
)

var bpfBandwidthListCmd = &cobra.Command{
	Use:   "list",
	Short: "List BPF datapath bandwidth settings",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf bandwidth list")

		bpfBandwidthList := make(map[string][]string)
		if err := bwmap.ThrottleMap.Dump(bpfBandwidthList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfBandwidthList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		listBandwidth(bpfBandwidthList)
	},
}

func listBandwidth(bpfBandwidthList map[string][]string) {
	if len(bpfBandwidthList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
		return
	}

	const (
		labelsIDTitle   = "IDENTITY"
		labelsBandwidth = "EGRESS BANDWIDTH (BitsPerSec)"
	)

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\n", labelsIDTitle, labelsBandwidth)

	const numColumns = 2
	rows := [][numColumns]string{}

	for key, value := range bpfBandwidthList {
		bps, _ := strconv.Atoi(value[0])
		bps *= 8
		quantity := resource.NewQuantity(int64(bps), resource.DecimalSI)
		rows = append(rows, [numColumns]string{key, quantity.String()})
	}

	sort.Slice(rows, func(i, j int) bool {
		for k := 0; k < numColumns; k++ {
			c := strings.Compare(rows[i][k], rows[j][k])

			if c != 0 {
				return c < 0
			}
		}

		return false
	})

	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\n", r[0], r[1])
	}

	w.Flush()
}

func init() {
	bpfBandwidthCmd.AddCommand(bpfBandwidthListCmd)
	command.AddJSONOutput(bpfBandwidthListCmd)
}
