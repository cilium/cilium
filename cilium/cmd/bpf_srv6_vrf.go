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
	srv6VRFListUsage = "List SRv6 VRF mappings."
)

type srv6VRF struct {
	SourceIP string
	DestCIDR string
	ID       uint32
}

var bpfSRv6VRFListCmd = &cobra.Command{
	Use:     "vrf",
	Aliases: []string{"ctx"},
	Short:   "List SRv6 VRF mappings",
	Long:    srv6VRFListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 vrf")

		if err := srv6map.OpenVRFMaps(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find SRv6 VRF mapping maps")
				return
			}

			Fatalf("Cannot open SRv6 VRF mapping maps: %s", err)
		}

		bpfVRFList := []srv6VRF{}
		parse := func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			bpfVRFList = append(bpfVRFList, srv6VRF{
				SourceIP: key.SourceIP.String(),
				DestCIDR: key.DestCIDR.String(),
				ID:       val.ID,
			})
		}

		if err := srv6map.SRv6VRFMap4.IterateWithCallback4(parse); err != nil {
			Fatalf("Error dumping contents of the IPv4 SRv6 VRF mapping map: %s\n", err)
		}
		if err := srv6map.SRv6VRFMap6.IterateWithCallback6(parse); err != nil {
			Fatalf("Error dumping contents of the IPv6 SRv6 VRF mapping map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfVRFList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfVRFList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printSRv6VRFList(bpfVRFList)
		}
	},
}

func printSRv6VRFList(vrfs []srv6VRF) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Source IP\tDestination CIDR\tVRF ID")
	for _, vrf := range vrfs {
		fmt.Fprintf(w, "%s\t%s\t%d\n", vrf.SourceIP, vrf.DestCIDR, vrf.ID)
	}

	w.Flush()
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6VRFListCmd)
	command.AddOutputOption(bpfSRv6VRFListCmd)
}
