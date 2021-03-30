// Copyright 2021 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/recorder"

	"github.com/spf13/cobra"
)

// bpfRecorderListCmd represents the bpf_recorder_list command
var bpfRecorderListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List PCAP recorder entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf recorder list")
		maps := make([]interface{}, 2)
		maps[0] = recorder.CaptureMap4
		maps[1] = recorder.CaptureMap6
		dumpRecorderEntries(maps)
	},
}

func init() {
	bpfRecorderCmd.AddCommand(bpfRecorderListCmd)
	command.AddJSONOutput(bpfRecorderListCmd)
}

func dumpRecorderEntries(maps []interface{}, args ...interface{}) {
	entries := make([]recorder.MapRecord, 0)

	for _, m := range maps {
		if m == nil {
			continue
		}
		path, err := m.(recorder.CaptureMap).Path()
		if err == nil {
			err = m.(recorder.CaptureMap).Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.(recorder.CaptureMap).Close()
		if command.OutputJSON() {
			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := recorder.MapRecord{Key: key.(recorder.RecorderKey), Value: value.(recorder.RecorderEntry)}
				entries = append(entries, record)
			}
			if err = m.(recorder.CaptureMap).DumpWithCallback(callback); err != nil {
				Fatalf("Error while collecting BPF map entries: %s", err)
			}
		} else {
			out, err := m.(recorder.CaptureMap).DumpEntries()
			if err != nil {
				Fatalf("Error while dumping BPF Map: %s", err)
			}
			fmt.Println(out)
		}
	}
	if command.OutputJSON() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
