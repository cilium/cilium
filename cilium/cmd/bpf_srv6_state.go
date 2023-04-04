// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/spf13/cobra"
)

const (
	srv6StateListUsage = "List SRv6 state entries."
)

type srv6State struct {
	innerSrc string
	innerDst string
	outerSrc string
	outerDst string
}

var bpfSRv6StateListCmd = &cobra.Command{
	Use:   "state",
	Short: "List SRv6 state entries",
	Long:  srv6StateListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 state")

		if err := srv6map.OpenStateMaps(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find SRv6 state maps")
				return
			}

			Fatalf("Cannot open SRv6 state maps: %s", err)
		}

		bpfStateList := []srv6State{}
		parse := func(key *srv6map.StateKey, val *srv6map.StateValue) {
			bpfStateList = append(bpfStateList, srv6State{
				innerSrc: key.InnerSrc.String(),
				innerDst: key.InnerDst.String(),
				outerSrc: val.OuterSrc.String(),
				outerDst: val.OuterDst.String(),
			})
		}

		if err := srv6map.SRv6StateMap4.IterateWithCallback4(parse); err != nil {
			Fatalf("Error dumping contents of the IPv4 SRv6 state map: %s\n", err)
		}
		if err := srv6map.SRv6StateMap6.IterateWithCallback6(parse); err != nil {
			Fatalf("Error dumping contents of the IPv6 SRv6 state map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfStateList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfStateList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printSRv6StateList(bpfStateList)
		}
	},
}

func printSRv6StateList(stateList []srv6State) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Inner Source\tInner Destination\tOuter Source\tOuter Destination")
	for _, state := range stateList {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", state.innerSrc, state.innerDst,
			state.outerSrc, state.outerDst)
	}

	w.Flush()
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6StateListCmd)
	command.AddOutputOption(bpfSRv6StateListCmd)
}
