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
		labelsPrio      = "PRIO"
	)

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\n", labelsIDTitle, labelsPrio, labelsBandwidth)

	const numColumns = 3
	rows := [][numColumns]string{}

	for key, value := range bpfBandwidthList {
		bps := 0
		prio := ""
		info := strings.Split(value[0], ",")
		if len(info) > 0 {
			bps, _ = strconv.Atoi(info[0])
		}
		if len(info) > 1 {
			prio = strings.TrimSpace(info[1])
		}
		bps *= 8
		quantity := resource.NewQuantity(int64(bps), resource.DecimalSI)
		rows = append(rows, [numColumns]string{key, prio, quantity.String()})
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
		fmt.Fprintf(w, "%s\t%s\t%s\n", r[0], r[1], r[2])
	}

	w.Flush()
}

func init() {
	BPFBandwidthCmd.AddCommand(bpfBandwidthListCmd)
	command.AddOutputOption(bpfBandwidthListCmd)
}
