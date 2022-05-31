// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/mountinfo"
)

// bpfmountfsShowCmd represents the bpf file system show command
var bpfmountfsShowCmd = &cobra.Command{
	Use:     "show",
	Short:   "Show bpf filesystem mount details",
	Example: "cilium bpf fs show",
	Run: func(cmd *cobra.Command, args []string) {
		getbpfmountFS(cmd, args)
	},
}

func init() {
	bpfmountFSCmd.AddCommand(bpfmountfsShowCmd)
	command.AddOutputOption(bpfmountfsShowCmd)
}

func getbpfmountFS(cmd *cobra.Command, args []string) {
	var mountfsStatus bool
	mountdetails, err := mountinfo.GetMountInfo()
	if err != nil {
		Fatalf("Unable to find the mount %s", err)
	}
	var bpfmountDetail *mountinfo.MountInfo
	for _, mountInfo := range mountdetails {
		if mountInfo.FilesystemType == "bpf" {
			mountfsStatus = true
			bpfmountDetail = mountInfo
			break
		}
	}
	if bpfmountDetail == nil {
		Fatalf("No BPF filesystems are mounted")
	}
	if command.OutputOption() {
		if err := command.PrintOutput(bpfmountDetail); err != nil {
			os.Exit(1)
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		fmt.Fprintf(w, "MountID:\t%d\n", bpfmountDetail.MountID)
		fmt.Fprintf(w, "ParentID:\t%d\n", bpfmountDetail.ParentID)
		fmt.Fprintf(w, "Mounted State:\t%t\n", mountfsStatus)
		fmt.Fprintf(w, "MountPoint:\t%s\n", bpfmountDetail.MountPoint)
		fmt.Fprintf(w, "MountOptions:\t%s\n", bpfmountDetail.MountOptions)
		fmt.Fprintf(w, "OptionFields:\t%s\n", bpfmountDetail.OptionalFields)
		fmt.Fprintf(w, "FilesystemType:\t%s\n", bpfmountDetail.FilesystemType)
		fmt.Fprintf(w, "MountSource:\t%s\n", bpfmountDetail.MountSource)
		fmt.Fprintf(w, "SuperOptions:\t%s\n", bpfmountDetail.SuperOptions)
		w.Flush()
	}
}
