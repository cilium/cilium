// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/bwmap"
)

var bpfBandwidthListCmd = &cobra.Command{
	Use:   "list",
	Short: "List BPF datapath bandwidth settings",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf bandwidth list")

		bpfBandwidthList := make(map[string][]string)
		if err := bwmap.ThrottleMap().Dump(bpfBandwidthList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfBandwidthList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
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
	command.AddOutputOption(bpfBandwidthListCmd)
}
