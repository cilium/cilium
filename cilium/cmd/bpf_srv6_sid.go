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
	srv6SIDListUsage = "List SRv6 SID entries.\n" + lpmWarningMessage
)

type srv6SID struct {
	SID   string
	VRFID uint32
}

var bpfSRv6SIDListCmd = &cobra.Command{
	Use:   "sid",
	Short: "List SRv6 SID entries",
	Long:  srv6SIDListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 sid")

		if err := srv6map.OpenSIDMap(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find SRv6 SID map")
				return
			}

			Fatalf("Cannot open SRv6 SID map: %s", err)
		}

		bpfSIDList := []srv6SID{}
		parse := func(key *srv6map.SIDKey, val *srv6map.SIDValue) {
			bpfSIDList = append(bpfSIDList, srv6SID{
				SID:   key.SID.String(),
				VRFID: val.VRFID,
			})
		}

		if err := srv6map.SRv6SIDMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of the SRv6 SID map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfSIDList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfSIDList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", lpmWarningMessage)
		} else {
			printSRv6SIDList(bpfSIDList)
		}
	},
}

func printSRv6SIDList(sidList []srv6SID) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "SID\tVRF ID")
	for _, sid := range sidList {
		fmt.Fprintf(w, "%s\t%d\n", sid.SID, sid.VRFID)
	}

	w.Flush()
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6SIDListCmd)
	command.AddOutputOption(bpfSRv6SIDListCmd)
}
