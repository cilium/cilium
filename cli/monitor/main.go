package monitor

/*
#cgo CFLAGS: -I../../bpf/include
#include <linux/perf_event.h>
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/codegangsta/cli"
	l "github.com/op/go-logging"

	"github.com/noironetworks/cilium-net/common/bpf"
)

var (
	log        = l.MustGetLogger("cilium-cli")
	CliCommand cli.Command
	dissect    = false
	config     = bpf.PerfEventConfig{
		MapPath:      "/sys/fs/bpf/tc/globals/cilium_events",
		Type:         C.PERF_TYPE_SOFTWARE,
		Config:       C.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   C.PERF_SAMPLE_RAW,
		WakeupEvents: 1,
	}
)

func receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	prefix := fmt.Sprintf("CPU %02d:", cpu)

	data := msg.DataDirect()
	if data[0] == bpf.CILIUM_NOTIFY_DROP {
		dn := bpf.DropNotify{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dn); err != nil {
			log.Warningf("Error while parsing drop notification message: %s\n", err)
		}
		dn.Dump(dissect, data, prefix)
	} else if data[0] == bpf.CILIUM_DBG_MSG {
		dm := bpf.DebugMsg{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dm); err != nil {
			log.Warningf("Error while parsing debug message: %s\n", err)
		} else {
			dm.Dump(data, prefix)
		}
	} else if data[0] == bpf.CILIUM_DBG_CAPTURE {
		dc := bpf.DebugCapture{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dc); err != nil {
			log.Warningf("Error while parsing debug capture message: %s\n", err)
		}
		dc.Dump(dissect, data, prefix)
	} else {
		fmt.Printf("%s Unknonwn event: %+v\n", prefix, msg)
	}
}

func run(ctx *cli.Context) {
	events, err := bpf.NewPerCpuEvents(&config)
	if err != nil {
		panic(err)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for _ = range signalChan {
			fmt.Println("\nReceived an interrupt, stopping monitor...\n")

			lost, unknown := events.Stats()
			if lost != 0 || unknown != 0 {
				log.Warningf("%d events lost, %d unknonwn notifications", lost, unknown)
			}

			if err := events.CloseAll(); err != nil {
				panic(err)
			}

			os.Exit(0)
		}
	}()

	for {
		todo, err := events.Poll(5000)
		if err != nil && err != syscall.EINTR {
			panic(err)
		}
		if todo > 0 {
			if err := events.ReadAll(receiveEvent); err != nil {
				log.Warningf("Error received while reading from perf buffer: %s", err)
			}
		}
	}

}

func init() {
	CliCommand = cli.Command{
		Name:  "monitor",
		Usage: "Monitor packet drop notifications",
		Flags: []cli.Flag{
			cli.IntFlag{
				Name:        "num-cpus, c",
				Usage:       "Number of CPUs",
				Value:       runtime.NumCPU(),
				EnvVar:      "__NR_CPUS__",
				Destination: &config.NumCpus,
			},
			cli.IntFlag{
				Name:        "num-pages, n",
				Usage:       "Number of pages for ring buffer",
				Value:       8,
				Destination: &config.NumPages,
			},
			cli.BoolFlag{
				Name:        "d",
				Usage:       "Dissect packet data",
				Destination: &dissect,
			},
		},
		Action: run,
	}
}
