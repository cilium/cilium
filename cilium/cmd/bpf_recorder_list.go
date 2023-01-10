// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/recorder"
)

// bpfRecorderListCmd represents the bpf_recorder_list command
var bpfRecorderListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List PCAP recorder entries",
	Run: func(_ *cobra.Command, _ []string) {
		common.RequireRootPrivilege("cilium bpf recorder list")
		maps := []recorder.CaptureMap{recorder.CaptureMap4()}
		if getIpv6EnableStatus() {
			maps = append(maps, recorder.CaptureMap6())
		}
		dumpRecorderEntries(maps)
	},
}

func init() {
	bpfRecorderCmd.AddCommand(bpfRecorderListCmd)
	command.AddOutputOption(bpfRecorderListCmd)
}

func dumpRecorderEntries(maps []recorder.CaptureMap) {
	entries := make([]recorder.MapRecord, 0)

	for _, m := range maps {
		if m == nil {
			continue
		}
		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.Close()
		if command.OutputOption() {
			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := recorder.MapRecord{Key: key.(recorder.RecorderKey), Value: value.(recorder.RecorderEntry)}
				entries = append(entries, record)
			}
			if err = m.DumpWithCallback(callback); err != nil {
				Fatalf("Error while collecting BPF map entries: %s", err)
			}
		} else {
			out, err := m.DumpEntries()
			if err != nil {
				Fatalf("Error while dumping BPF Map: %s", err)
			}
			fmt.Println(out)
		}
	}
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
