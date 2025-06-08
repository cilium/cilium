// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/monitor/api"
)

const (
	// RecorderCaptureLen is the amount of data in the RecorderCapture message
	RecorderCaptureLen = 24
)

// RecorderCapture is the message format of a pcap capture in the bpf ring buffer
type RecorderCapture struct {
	Type     uint8
	SubType  uint8
	RuleID   uint16
	Reserved uint32
	TimeBoot uint64
	CapLen   uint32
	Len      uint32
	// data
}

// Dump prints the message according to the verbosity level specified
func (n *RecorderCapture) Dump(args *api.DumpArgs) {
	n.DumpInfo(args.Data)
}

// DumpInfo prints a summary of the recorder notify messages.
func (n *RecorderCapture) DumpInfo(data []byte) {
	buf := bufio.NewWriter(os.Stdout)
	dir := "egress"
	if n.SubType == 1 {
		dir = "ingress"
	}
	fmt.Fprintf(buf, "Recorder capture: dir:%s rule:%d ts:%d caplen:%d len:%d\n",
		dir, int(n.RuleID), int(n.TimeBoot), int(n.CapLen), int(n.Len))
	buf.Flush()
	Dissect(true, data[RecorderCaptureLen:])
	fmt.Fprintf(buf, "----\n")
	buf.Flush()
}
