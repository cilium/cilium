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

	"github.com/noironetworks/cilium-net/common/bpf"
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
			events.ReadAll(receiveEvent)
		}
	}

	if err := events.CloseAll(); err != nil {
		panic(err)
	}

}
