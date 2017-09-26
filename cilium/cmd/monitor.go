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
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/bpfdebug"
	"github.com/cilium/cilium/pkg/byteorder"

	"github.com/spf13/cobra"
)

const (
	msgSeparator = "------------------------------------------------------------------------------"
	connTimeout  = 12 * time.Second
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitoring",
	Long: `The monitor displays notifications and events emitted by the BPF
programs attached to endpoints and devices. This includes:
  * Dropped packet notifications
  * Captured packet traces
  * Debugging information`,
	Run: func(cmd *cobra.Command, args []string) {
		runMonitor()
	},
}

// Verbosity levels for formatting output.
type Verbosity uint8

const (
	// INFO is the level of verbosity in which summaries of Drop and Capture
	// messages are printed out when the monitor is invoked
	INFO Verbosity = iota + 1
	// DEBUG is the level of verbosity in which more information about packets
	// is printed than in INFO mode. Debug, Drop, and Capture messages are printed.
	DEBUG
	// VERBOSE is the level of verbosity in which the most information possible
	// about packets is printed out. Currently is not utilized.
	VERBOSE
)

func listEventTypes() []string {
	types := []string{}
	for k := range eventTypes {
		types = append(types, k)
	}
	return types
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().BoolVar(&hex, "hex", false, "Do not dissect, print payload in HEX")
	monitorCmd.Flags().StringVarP(&eventType, "type", "t", "", fmt.Sprintf("Filter by event types %v", listEventTypes()))
	monitorCmd.Flags().Uint16Var(&fromSource, "from", 0, "Filter by source endpoint id")
	monitorCmd.Flags().Uint16Var(&toDst, "to", 0, "Filter by destination endpoint id")
	monitorCmd.Flags().Uint16Var(&related, "related-to", 0, "Filter by either source or destination endpoint id")
	monitorCmd.Flags().BoolVarP(&verboseMonitor, "verbose", "v", false, "Enable verbose output")
}

var (
	hex         = false
	eventConfig = bpf.PerfEventConfig{
		MapName:      bpf.EventsMapName,
		Type:         bpf.PERF_TYPE_SOFTWARE,
		Config:       bpf.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   bpf.PERF_SAMPLE_RAW,
		WakeupEvents: 1,
	}
	eventTypeIdx = bpfdebug.MessageTypeUnspec // for integer comparison
	eventType    = ""
	eventTypes   = map[string]int{
		"drop":    bpfdebug.MessageTypeDrop,
		"debug":   bpfdebug.MessageTypeDebug,
		"capture": bpfdebug.MessageTypeCapture,
		"trace":   bpfdebug.MessageTypeTrace,
	}
	fromSource     = uint16(0)
	toDst          = uint16(0)
	related        = uint16(0)
	verboseMonitor = false
	verbosity      = INFO
)

func setVerbosity() {
	if verboseMonitor {
		verbosity = DEBUG
	} else {
		verbosity = INFO
	}
}

func lostEvent(lost uint64, cpu int) {
	fmt.Printf("CPU %02d: Lost %d events\n", cpu, lost)
}

// match checks if the event type, from endpoint and / or to endpoint match
// when they are supplied. The either part of from and to endpoint depends on
// related to, which can match on both.  If either one of them is less than or
// equal to zero, then it is assumed user did not use them.
func match(messageType int, src uint16, dst uint16) bool {
	if eventTypeIdx != bpfdebug.MessageTypeUnspec && messageType != eventTypeIdx {
		return false
	} else if fromSource > 0 && fromSource != src {
		return false
	} else if toDst > 0 && toDst != dst {
		return false
	} else if related > 0 && related != src && related != dst {
		return false
	}

	return true
}

// dropEvents prints out all the received drop notifications.
func dropEvents(prefix string, data []byte) {
	dn := bpfdebug.DropNotify{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dn); err != nil {
		fmt.Printf("Error while parsing drop notification message: %s\n", err)
	}
	if match(bpfdebug.MessageTypeDrop, dn.Source, uint16(dn.DstID)) {
		if verbosity == INFO {
			dn.DumpInfo(data)
		} else {
			fmt.Println(msgSeparator)
			dn.DumpVerbose(!hex, data, prefix)
		}
	}
}

// traceEvents prints out all the received trace notifications.
func traceEvents(prefix string, data []byte) {
	tn := bpfdebug.TraceNotify{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &tn); err != nil {
		fmt.Printf("Error while parsing trace notification message: %s\n", err)
	}
	if match(bpfdebug.MessageTypeTrace, tn.Source, tn.DstID) {
		if verbosity == INFO {
			tn.DumpInfo(data)
		} else {
			fmt.Println(msgSeparator)
			tn.DumpVerbose(!hex, data, prefix)
		}
	}
}

// debugEvents prints out all the debug messages.
func debugEvents(prefix string, data []byte) {
	dm := bpfdebug.DebugMsg{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dm); err != nil {
		fmt.Printf("Error while parsing debug message: %s\n", err)
	}
	if match(bpfdebug.MessageTypeDebug, dm.Source, 0) {
		if verbosity == INFO {
			dm.DumpInfo(data)
		} else {
			dm.Dump(data, prefix)
		}
	}
}

// captureEvents prints out all the capture messages.
func captureEvents(prefix string, data []byte) {
	dc := bpfdebug.DebugCapture{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dc); err != nil {
		fmt.Printf("Error while parsing debug capture message: %s\n", err)
	}
	if match(bpfdebug.MessageTypeCapture, dc.Source, 0) {
		if verbosity == INFO {
			dc.DumpInfo(data)
		} else {
			fmt.Println(msgSeparator)
			dc.DumpVerbose(!hex, data, prefix)
		}
	}
}

// receiveEvent forwards all the per CPU events to the appropriate type function.
func receiveEvent(data []byte, cpu int) {
	prefix := fmt.Sprintf("CPU %02d:", cpu)
	messageType := data[0]

	switch messageType {
	case bpfdebug.MessageTypeDrop:
		dropEvents(prefix, data)
	case bpfdebug.MessageTypeDebug:
		debugEvents(prefix, data)
	case bpfdebug.MessageTypeCapture:
		captureEvents(prefix, data)
	case bpfdebug.MessageTypeTrace:
		traceEvents(prefix, data)
	default:
		fmt.Printf("%s Unknown event: %+v\n", prefix, data)
	}
}

// validateEventTypeFilter does some input validation to give the user feedback if they
// wrote something close that did not match for example 'srop' instead of
// 'drop'.
func validateEventTypeFilter() {
	i, err := eventTypes[eventType]
	if !err {
		err := "Unknown type (%s). Please use one of the following ones %v\n"
		fmt.Printf(err, eventType, listEventTypes())
		os.Exit(1)
	}
	eventTypeIdx = i
}

func setupSigHandler() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			fmt.Printf("\nReceived an interrupt, disconnecting from monitor...\n\n")
			os.Exit(0)
		}
	}()
}

func runMonitor() {
	setVerbosity()
	setupSigHandler()
	if resp, err := client.Daemon.GetHealthz(nil); err == nil {
		if nm := resp.Payload.NodeMonitor; nm != nil {
			fmt.Printf("Listening for events on %d CPUs with %dx%d of shared memory\n",
				nm.Cpus, nm.Npages, nm.Pagesize)
		}
	}
	fmt.Printf("Press Ctrl-C to quit\n")
start:
	conn, err := net.Dial("unix", defaults.MonitorSockPath)
	if err != nil {
		fmt.Printf("Error: unable to connect to monitor %s\n", err)
		os.Exit(1)
	}

	defer conn.Close()

	if eventType != "" {
		validateEventTypeFilter()
	}

	var meta payload.Meta
	var pl payload.Payload
	for {
		if err := payload.ReadMetaPayload(conn, &meta, &pl); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// EOF may be due to invalid payload size. Close the connection just in case.
				conn.Close()
				log.WithError(err).Warn("connection closed")
				time.Sleep(connTimeout)
				goto start
			} else {
				log.WithError(err).Fatal("decoding error")
			}
		}

		if pl.Type == payload.EventSample {
			receiveEvent(pl.Data, pl.CPU)
		} else /* if pl.Type == payload.RecordLost */ {
			lostEvent(pl.Lost, pl.CPU)
		}
	}
}
