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
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/monitor"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

type uint16Flags []uint16

var _ pflag.Value = &uint16Flags{}

func (i *uint16Flags) String() string {
	pieces := make([]string, 0, len(*i))
	for _, v := range *i {
		pieces = append(pieces, strconv.Itoa(int(v)))
	}
	return strings.Join(pieces, ", ")
}

func (i *uint16Flags) Set(value string) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*i = append(*i, uint16(v))
	return nil
}

func (i *uint16Flags) Type() string {
	return "[]uint16"
}

func (i *uint16Flags) has(value uint16) bool {
	for _, v := range *i {
		if v == value {
			return true
		}
	}

	return false
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
	types := make([]string, len(eventTypes))
	i := 0
	for k := range eventTypes {
		types[i] = k
		i++
	}
	sort.Strings(types)
	return types
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().BoolVar(&hex, "hex", false, "Do not dissect, print payload in HEX")
	monitorCmd.Flags().StringVarP(&eventType, "type", "t", "", fmt.Sprintf("Filter by event types %v", listEventTypes()))
	monitorCmd.Flags().Var(&fromSource, "from", "Filter by source endpoint id")
	monitorCmd.Flags().Var(&toDst, "to", "Filter by destination endpoint id")
	monitorCmd.Flags().Var(&related, "related-to", "Filter by either source or destination endpoint id")
	monitorCmd.Flags().BoolVarP(&verboseMonitor, "verbose", "v", false, "Enable verbose output")
}

var (
	hex          = false
	eventTypeIdx = monitor.MessageTypeUnspec // for integer comparison
	eventType    = ""
	eventTypes   = map[string]int{
		"drop":    monitor.MessageTypeDrop,
		"debug":   monitor.MessageTypeDebug,
		"capture": monitor.MessageTypeCapture,
		"trace":   monitor.MessageTypeTrace,
	}
	fromSource     = uint16Flags{}
	toDst          = uint16Flags{}
	related        = uint16Flags{}
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
	if eventTypeIdx != monitor.MessageTypeUnspec && messageType != eventTypeIdx {
		return false
	} else if len(fromSource) > 0 && !fromSource.has(src) {
		return false
	} else if len(toDst) > 0 && !toDst.has(dst) {
		return false
	} else if len(related) > 0 && !related.has(src) && !related.has(dst) {
		return false
	}

	return true
}

// dropEvents prints out all the received drop notifications.
func dropEvents(prefix string, data []byte) {
	dn := monitor.DropNotify{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dn); err != nil {
		fmt.Printf("Error while parsing drop notification message: %s\n", err)
	}
	if match(monitor.MessageTypeDrop, dn.Source, uint16(dn.DstID)) {
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
	tn := monitor.TraceNotify{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &tn); err != nil {
		fmt.Printf("Error while parsing trace notification message: %s\n", err)
	}
	if match(monitor.MessageTypeTrace, tn.Source, tn.DstID) {
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
	dm := monitor.DebugMsg{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dm); err != nil {
		fmt.Printf("Error while parsing debug message: %s\n", err)
	}
	if match(monitor.MessageTypeDebug, dm.Source, 0) {
		if verbosity == INFO {
			dm.DumpInfo(data)
		} else {
			dm.Dump(data, prefix)
		}
	}
}

// captureEvents prints out all the capture messages.
func captureEvents(prefix string, data []byte) {
	dc := monitor.DebugCapture{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dc); err != nil {
		fmt.Printf("Error while parsing debug capture message: %s\n", err)
	}
	if match(monitor.MessageTypeCapture, dc.Source, 0) {
		if verbosity == INFO {
			dc.DumpInfo(data)
		} else {
			fmt.Println(msgSeparator)
			dc.DumpVerbose(!hex, data, prefix)
		}
	}
}

// logRecordEvents prints out LogRecord events
func logRecordEvents(prefix string, data []byte) {
	buf := bytes.NewBuffer(data[1:])
	dec := gob.NewDecoder(buf)

	lr := monitor.LogRecordNotify{}
	if err := dec.Decode(&lr); err != nil {
		fmt.Printf("Error while decoding LogRecord notification message: %s\n", err)
	}

	lr.DumpInfo()
}

// agentEvents prints out agent events
func agentEvents(prefix string, data []byte) {
	buf := bytes.NewBuffer(data[1:])
	dec := gob.NewDecoder(buf)

	an := monitor.AgentNotify{}
	if err := dec.Decode(&an); err != nil {
		fmt.Printf("Error while decoding agent notification message: %s\n", err)
	}

	an.DumpInfo()
}

// receiveEvent forwards all the per CPU events to the appropriate type function.
func receiveEvent(data []byte, cpu int) {
	prefix := fmt.Sprintf("CPU %02d:", cpu)
	messageType := data[0]

	switch messageType {
	case monitor.MessageTypeDrop:
		dropEvents(prefix, data)
	case monitor.MessageTypeDebug:
		debugEvents(prefix, data)
	case monitor.MessageTypeCapture:
		captureEvents(prefix, data)
	case monitor.MessageTypeTrace:
		traceEvents(prefix, data)
	case monitor.MessageTypeAccessLog:
		logRecordEvents(prefix, data)
	case monitor.MessageTypeAgent:
		agentEvents(prefix, data)
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
