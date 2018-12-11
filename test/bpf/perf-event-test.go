// Copyright 2016-2018 Authors of Cilium
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

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/bpf"

	"github.com/spf13/cobra"
)

var (
	config = bpf.PerfEventConfig{
		MapName:      "perf_test_events",
		Type:         bpf.PERF_TYPE_SOFTWARE,
		Config:       bpf.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   bpf.PERF_SAMPLE_RAW,
		WakeupEvents: 1,
	}
)

func receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	fmt.Printf("%+v\n", msg)
}

func lostEvent(lost *bpf.PerfEventLost, cpu int) {
	fmt.Printf("Lost %d\n", lost.Lost)
}

func errEvent(err *bpf.PerfEvent) {
	fmt.Printf("Error\n")
}

var RootCmd = &cobra.Command{
	Use:   "perf-event-test",
	Short: "Test utility for perf events",
	Run: func(cmd *cobra.Command, args []string) {
		events, err := bpf.NewPerCpuEvents(&config)
		if err != nil {
			panic(err)
		}

		for {
			todo, err := events.Poll(-1)
			if err != nil {
				panic(err)
			}
			if todo > 0 {
				events.ReadAll(receiveEvent, lostEvent, errEvent)
			}
		}

	},
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(-1)
	}
}

func init() {
	flags := RootCmd.PersistentFlags()
	flags.IntVarP(&config.NumCpus, "num-cpus", "c", 1, "Number of CPUs")
	flags.IntVarP(&config.NumPages, "num-pagse", "n", 8, "Number of pages for ring buffer")
}
