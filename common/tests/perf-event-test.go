//
// Copyright 2016 Authors of Cilium
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
//
package main

/*
#cgo CFLAGS: -I../../bpf/include
#include <linux/perf_event.h>
*/
import "C"

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"

	"github.com/cilium/cilium/common/bpf"
)

var (
	config = bpf.PerfEventConfig{
		MapPath:      "/sys/fs/bpf/tc/globals/perf_test_events",
		Type:         C.PERF_TYPE_SOFTWARE,
		Config:       C.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   C.PERF_SAMPLE_RAW,
		WakeupEvents: 1,
	}
)

func main() {
	app := cli.NewApp()
	app.Name = "perf-event-test"
	app.Usage = "Test utility for perf events"
	app.Version = "0.1.0"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:        "num-cpus, c",
			Usage:       "Number of CPUs",
			Value:       1,
			EnvVar:      "__NR_CPUS__",
			Destination: &config.NumCpus,
		},
		cli.IntFlag{
			Name:        "num-pages, n",
			Usage:       "Number of pages for ring buffer",
			Value:       8,
			Destination: &config.NumPages,
		},
	}
	app.Action = run
	app.Run(os.Args)
}

func receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	fmt.Printf("%+v\n", msg)
}

func lostEvent(lost *bpf.PerfEventLost, cpu int) {
	fmt.Printf("Lost %d\n", lost.Lost)
}

func run(ctx *cli.Context) {
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
			events.ReadAll(receiveEvent, lostEvent)
		}
	}

	//if err := events.CloseAll(); err != nil {
	//	panic(err)
	//}

}
