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
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/mountinfo"

	"github.com/spf13/cobra"
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
	command.AddJSONOutput(bpfmountfsShowCmd)
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
	if command.OutputJSON() {
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
