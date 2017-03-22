// Copyright 2017 Authors of Cilium
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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/bpfdebug"

	"github.com/spf13/cobra"
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitoring",
	Long: `The monitor displays notifications and events omitted by the BPF
programs attached to endpoints and devices. This includes:
  * Dropped packet notifications
  * Captured packet traces
  * Debugging information`,
	Run: func(cmd *cobra.Command, args []string) {
		runMonitor()
	},
}

func init() {
	RootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().IntVarP(&eventConfig.NumCpus, "num-cpus", "c", runtime.NumCPU(), "Number of CPUs")
	monitorCmd.Flags().IntVarP(&eventConfig.NumPages, "num-pages", "n", 64, "Number of pages for ring buffer")
	monitorCmd.Flags().BoolVarP(&dissect, "dissect", "d", false, "Dissect packet data")
}

var (
	dissect     = false
	eventConfig = bpf.PerfEventConfig{
		MapName:      bpf.EventsMapName,
		Type:         bpf.PERF_TYPE_SOFTWARE,
		Config:       bpf.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   bpf.PERF_SAMPLE_RAW,
		WakeupEvents: 1,
	}
)

func lostEvent(lost *bpf.PerfEventLost, cpu int) {
	fmt.Printf("Lost %d events\n", lost.Lost)
}

func receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	prefix := fmt.Sprintf("CPU %02d:", cpu)

	data := msg.DataDirect()
	if data[0] == bpfdebug.MessageTypeDrop {
		dn := bpfdebug.DropNotify{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dn); err != nil {
			fmt.Printf("Error while parsing drop notification message: %s\n", err)
		}
		dn.Dump(dissect, data, prefix)
	} else if data[0] == bpfdebug.MessageTypeDebug {
		dm := bpfdebug.DebugMsg{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dm); err != nil {
			fmt.Printf("Error while parsing debug message: %s\n", err)
		} else {
			dm.Dump(data, prefix)
		}
	} else if data[0] == bpfdebug.MessageTypeCapture {
		dc := bpfdebug.DebugCapture{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dc); err != nil {
			fmt.Printf("Error while parsing debug capture message: %s\n", err)
		}
		dc.Dump(dissect, data, prefix)
	} else {
		fmt.Printf("%s Unknonwn event: %+v\n", prefix, msg)
	}
}

func runMonitor() {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run the monitor with root privileges.\n")
		os.Exit(1)
	}

	events, err := bpf.NewPerCpuEvents(&eventConfig)
	if err != nil {
		panic(err)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			fmt.Printf("\nReceived an interrupt, stopping monitor...\n\n")

			lost, unknown := events.Stats()
			if lost != 0 || unknown != 0 {
				fmt.Printf("%d events lost, %d unknown notifications\n", lost, unknown)
			}

			if err := events.CloseAll(); err != nil {
				panic(err)
			}

			os.Exit(0)
		}
	}()

	fmt.Printf("Listening for events on %d CPUs with %dx%d of shared memory\n",
		events.Cpus, events.Npages, events.Pagesize)
	fmt.Printf("Press Ctrl-C to quit\n")

	for {
		todo, err := events.Poll(5000)
		if err != nil && err != syscall.EINTR {
			panic(err)
		}
		if todo > 0 {
			if err := events.ReadAll(receiveEvent, lostEvent); err != nil {
				fmt.Printf("Error received while reading from perf buffer: %s\n", err)
			}
		}
	}

}
