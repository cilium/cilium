// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"bufio"
	"bytes"
	"encoding/binary"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
)

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
	// JSON is the level of verbosity in which event information is printed out in json format
	JSON
)

// DisplayFormat is used to determine how to display the endpoint
type DisplayFormat bool

const (
	// DisplayLabel is used to display the endpoint as a label
	DisplayLabel DisplayFormat = false
	// DisplayHex is used to display the endpoint as a number
	DisplayNumeric DisplayFormat = true
)

// DumpArgs is used to pass arguments to the Dump method
type DumpArgs struct {
	Data        []byte
	CpuPrefix   string
	Format      DisplayFormat
	LinkMonitor getters.LinkGetter
	Dissect     bool
	Verbosity   Verbosity
	Buf         *bufio.Writer
}

// MonitorEvent is the interface that all monitor events must implement to be dumped
type MonitorEvent interface {
	// Decode decodes the message in 'data' into the struct.
	Decode(data []byte) error
	// GetSrc retrieves the source endpoint for the message
	GetSrc() (src uint16)
	// GetDst retrieves the destination endpoint for the message.
	GetDst() (dst uint16)
	// Dump prints the message according to the verbosity level specified
	Dump(args *DumpArgs)
}

// DefaultDecoder is a default implementation of the Decode method
type DefaultDecoder struct{}

// Decode decodes the message in 'data' into the struct.
func (d *DefaultDecoder) Decode(data []byte) error {
	return binary.Read(bytes.NewReader(data), binary.NativeEndian, d)
}

// DefaultSrcDstGetter is a default implementation of the GetSrc and GetDst methods
type DefaultSrcDstGetter struct{}

// GetSrc retrieves the source endpoint for the message
func (d *DefaultSrcDstGetter) GetSrc() (src uint16) {
	return 0
}

// GetDst retrieves the destination endpoint for the message.
func (d *DefaultSrcDstGetter) GetDst() (dst uint16) {
	return 0
}
