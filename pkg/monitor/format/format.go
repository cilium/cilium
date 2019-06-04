// Copyright 2018 Authors of Cilium
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

package format

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "monitor-format")

// Verbosity levels for formatting output.
type Verbosity uint8

const (
	msgSeparator = "------------------------------------------------------------------------------"

	// INFO is the level of verbosity in which summaries of Drop and Capture
	// messages are printed out when the monitor is invoked
	INFO Verbosity = iota + 1
	// DEBUG is the level of verbosity in which more information about packets
	// is printed than in INFO mode. Debug, Drop, and Capture messages are printed.
	DEBUG
	// VERBOSE is the level of verbosity in which the most information possible
	// about packets is printed out. Currently is not utilized.
	VERBOSE
	// JSON is the level of verbosity in which event information is printed out in json format
	JSON
)

// MonitorFormatter filters and formats monitor messages from a buffer.
type MonitorFormatter struct {
	EventTypes monitorAPI.MessageTypeFilter
	FromSource Uint16Flags
	ToDst      Uint16Flags
	Related    Uint16Flags
	Verbose    bool
	Hex        bool
	JSONOutput bool
	Verbosity  Verbosity
}

// NewMonitorFormatter returns a new formatter with default configuration.
func NewMonitorFormatter(verbosity Verbosity) *MonitorFormatter {
	return &MonitorFormatter{
		Hex:        false,
		EventTypes: monitorAPI.MessageTypeFilter{},
		FromSource: Uint16Flags{},
		ToDst:      Uint16Flags{},
		Related:    Uint16Flags{},
		Verbose:    false,
		JSONOutput: false,
		Verbosity:  verbosity,
	}
}

// match checks if the event type, from endpoint and / or to endpoint match
// when they are supplied. The either part of from and to endpoint depends on
// related to, which can match on both.  If either one of them is less than or
// equal to zero, then it is assumed user did not use them.
func (m *MonitorFormatter) match(messageType int, src uint16, dst uint16) bool {
	if len(m.EventTypes) > 0 && !m.EventTypes.Contains(messageType) {
		return false
	} else if len(m.FromSource) > 0 && !m.FromSource.Has(src) {
		return false
	} else if len(m.ToDst) > 0 && !m.ToDst.Has(dst) {
		return false
	} else if len(m.Related) > 0 && !m.Related.Has(src) && !m.Related.Has(dst) {
		return false
	}

	return true
}

// dropEvents prints out all the received drop notifications.
func (m *MonitorFormatter) dropEvents(prefix string, data []byte) {
	dn := monitor.DropNotify{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dn); err != nil {
		fmt.Printf("Error while parsing drop notification message: %s\n", err)
	}
	if m.match(monitorAPI.MessageTypeDrop, dn.Source, uint16(dn.DstID)) {
		switch m.Verbosity {
		case INFO:
			dn.DumpInfo(data)
		case JSON:
			dn.DumpJSON(data, prefix)
		default:
			fmt.Println(msgSeparator)
			dn.DumpVerbose(!m.Hex, data, prefix)
		}
	}
}

// traceEvents prints out all the received trace notifications.
func (m *MonitorFormatter) traceEvents(prefix string, data []byte) {
	tn := monitor.TraceNotify{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &tn); err != nil {
		fmt.Printf("Error while parsing trace notification message: %s\n", err)
	}
	if m.match(monitorAPI.MessageTypeTrace, tn.Source, tn.DstID) {
		switch m.Verbosity {
		case INFO:
			tn.DumpInfo(data)
		case JSON:
			tn.DumpJSON(data, prefix)
		default:
			fmt.Println(msgSeparator)
			tn.DumpVerbose(!m.Hex, data, prefix)
		}
	}
}

// debugEvents prints out all the debug messages.
func (m *MonitorFormatter) debugEvents(prefix string, data []byte) {
	dm := monitor.DebugMsg{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dm); err != nil {
		fmt.Printf("Error while parsing debug message: %s\n", err)
	}
	if m.match(monitorAPI.MessageTypeDebug, dm.Source, 0) {
		switch m.Verbosity {
		case INFO:
			dm.DumpInfo(data)
		case JSON:
			dm.DumpJSON(prefix)
		default:
			dm.Dump(prefix)
		}
	}
}

// captureEvents prints out all the capture messages.
func (m *MonitorFormatter) captureEvents(prefix string, data []byte) {
	dc := monitor.DebugCapture{}

	if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dc); err != nil {
		fmt.Printf("Error while parsing debug capture message: %s\n", err)
	}
	if m.match(monitorAPI.MessageTypeCapture, dc.Source, 0) {
		switch m.Verbosity {
		case INFO:
			dc.DumpInfo(data)
		case JSON:
			dc.DumpJSON(data, prefix)
		default:
			fmt.Println(msgSeparator)
			dc.DumpVerbose(!m.Hex, data, prefix)
		}
	}
}

// logRecordEvents prints out LogRecord events
func (m *MonitorFormatter) logRecordEvents(prefix string, data []byte) {
	buf := bytes.NewBuffer(data[1:])
	dec := gob.NewDecoder(buf)

	lr := monitor.LogRecordNotify{}
	if err := dec.Decode(&lr); err != nil {
		fmt.Printf("Error while decoding LogRecord notification message: %s\n", err)
	}

	if m.match(monitorAPI.MessageTypeAccessLog, uint16(lr.SourceEndpoint.ID), uint16(lr.DestinationEndpoint.ID)) {
		if m.Verbosity == JSON {
			lr.DumpJSON()
		} else {
			lr.DumpInfo()
		}
	}
}

// agentEvents prints out agent events
func (m *MonitorFormatter) agentEvents(prefix string, data []byte) {
	buf := bytes.NewBuffer(data[1:])
	dec := gob.NewDecoder(buf)

	an := monitorAPI.AgentNotify{}
	if err := dec.Decode(&an); err != nil {
		fmt.Printf("Error while decoding agent notification message: %s\n", err)
	}

	if m.match(monitorAPI.MessageTypeAgent, 0, 0) {
		if m.Verbosity == JSON {
			an.DumpJSON()
		} else {
			an.DumpInfo()
		}
	}
}

// FormatSample prints an event from the provided raw data slice to stdout.
//
// For most monitor event types, 'data' corresponds to the 'data' field in
// bpf.PerfEventSample. Exceptions are MessageTypeAccessLog and
// MessageTypeAgent.
func (m *MonitorFormatter) FormatSample(data []byte, cpu int) {
	prefix := fmt.Sprintf("CPU %02d:", cpu)
	messageType := data[0]

	switch messageType {
	case monitorAPI.MessageTypeDrop:
		m.dropEvents(prefix, data)
	case monitorAPI.MessageTypeDebug:
		m.debugEvents(prefix, data)
	case monitorAPI.MessageTypeCapture:
		m.captureEvents(prefix, data)
	case monitorAPI.MessageTypeTrace:
		m.traceEvents(prefix, data)
	case monitorAPI.MessageTypeAccessLog:
		m.logRecordEvents(prefix, data)
	case monitorAPI.MessageTypeAgent:
		m.agentEvents(prefix, data)
	default:
		fmt.Printf("%s Unknown event: %+v\n", prefix, data)
	}
}

// LostEvent formats a lost event using the specified payload parameters.
func LostEvent(lost uint64, cpu int) {
	fmt.Printf("CPU %02d: Lost %d events\n", cpu, lost)
}

// FormatEvent formats an event from the specified payload to stdout.
//
// Returns true if the event was successfully printed, false otherwise.
func (m *MonitorFormatter) FormatEvent(pl *payload.Payload) bool {
	switch pl.Type {
	case payload.EventSample:
		m.FormatSample(pl.Data, pl.CPU)
	case payload.RecordLost:
		LostEvent(pl.Lost, pl.CPU)
	default:
		return false
	}

	return true
}
