// Copyright 2021 Authors of Cilium
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

package monitor

import (
	"bufio"
	"fmt"
	"os"
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
