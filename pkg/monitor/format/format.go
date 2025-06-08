// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package format

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

// MonitorFormatter filters and formats monitor messages from a buffer.
type MonitorFormatter struct {
	EventTypes monitorAPI.MessageTypeFilter
	FromSource Uint16Flags
	ToDst      Uint16Flags
	Related    Uint16Flags
	Hex        bool
	JSONOutput bool
	Verbosity  monitorAPI.Verbosity
	Numeric    bool

	linkMonitor getters.LinkGetter
}

// NewMonitorFormatter returns a new formatter with default configuration.
func NewMonitorFormatter(verbosity monitorAPI.Verbosity, linkMonitor getters.LinkGetter) *MonitorFormatter {
	return &MonitorFormatter{
		Hex:         false,
		EventTypes:  monitorAPI.MessageTypeFilter{},
		FromSource:  Uint16Flags{},
		ToDst:       Uint16Flags{},
		Related:     Uint16Flags{},
		JSONOutput:  false,
		Verbosity:   verbosity,
		Numeric:     bool(monitorAPI.DisplayLabel),
		linkMonitor: linkMonitor,
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

// FormatSample prints an event from the provided raw data slice to stdout.
//
// For most monitor event types, 'data' corresponds to the 'data' field in
// bpf.PerfEventSample. Exceptions are MessageTypeAccessLog and
// MessageTypeAgent.
func (m *MonitorFormatter) FormatSample(data []byte, cpu int) {
	prefix := fmt.Sprintf("CPU %02d:", cpu)
	messageType := int(data[0])
	var msg monitorAPI.MonitorEvent
	switch messageType {
	case monitorAPI.MessageTypeDrop:
		msg = &monitor.DropNotify{}
	case monitorAPI.MessageTypeDebug:
		msg = &monitor.DebugMsg{}
	case monitorAPI.MessageTypeCapture:
		msg = &monitor.DebugCapture{}
	case monitorAPI.MessageTypeTrace:
		msg = &monitor.TraceNotify{}
	case monitorAPI.MessageTypeAccessLog:
		msg = &monitor.LogRecordNotify{}
	case monitorAPI.MessageTypeAgent:
		msg = &monitorAPI.AgentNotify{}
	case monitorAPI.MessageTypePolicyVerdict:
		msg = &monitor.PolicyVerdictNotify{}
	case monitorAPI.MessageTypeRecCapture:
		msg = &monitor.RecorderCapture{}
	case monitorAPI.MessageTypeTraceSock:
		msg = &monitor.TraceSockNotify{}
	default:
		fmt.Printf("%s Unknown event: %+v\n", prefix, data)
		return
	}

	if err := msg.Decode(data); err != nil {
		fmt.Printf("cannot decode message type '%d': %v\n", messageType, err)
		return
	}

	// For TraceSockNotify we don't implement any matching logic.
	// See the original implementation: https://github.com/cilium/cilium/pull/21516#discussion_r984194699
	_, isTraceSock := msg.(*monitor.TraceSockNotify)
	if !isTraceSock && !m.match(messageType, msg.GetSrc(), msg.GetDst()) {
		return
	}

	msg.Dump(&monitorAPI.DumpArgs{
		Data:        data,
		CpuPrefix:   prefix,
		Format:      monitorAPI.DisplayFormat(m.Numeric),
		LinkMonitor: m.linkMonitor,
		Dissect:     !m.Hex,
		Verbosity:   m.Verbosity,
	})
}

// LostEvent formats a lost event using the specified payload parameters.
func (m *MonitorFormatter) LostEvent(lost uint64, cpu int) {
	fmt.Printf("CPU %02d: Lost %d events\n", cpu, lost)
}

// UnknownEvent formats an unknown event using the specified payload parameters.
func (m *MonitorFormatter) UnknownEvent(lost uint64, cpu int, t int) {
	fmt.Printf("Unknown payload type: %d, CPU %02d: Lost %d events\n", t, cpu, lost)
}

// FormatEvent formats an event from the specified payload to stdout.
//
// Returns true if the event was successfully recognized, false otherwise.
func (m *MonitorFormatter) FormatEvent(pl *payload.Payload) bool {
	switch pl.Type {
	case payload.EventSample:
		m.FormatSample(pl.Data, pl.CPU)
	case payload.RecordLost:
		m.LostEvent(pl.Lost, pl.CPU)
	default:
		m.UnknownEvent(pl.Lost, pl.CPU, pl.Type)
		return false
	}

	return true
}
