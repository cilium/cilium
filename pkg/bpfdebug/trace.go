// Copyright 2016-2017 Authors of Cilium
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

package bpfdebug

import (
	"fmt"
)

const (
	// TraceNotifyLen is the amount of packet data provided in a trace notification
	TraceNotifyLen = 32
)

// TraceNotify is the message format of a trace notification in the BPF ring buffer
type TraceNotify struct {
	Type     uint8
	ObsPoint uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint32
	SrcLabel uint32
	DstLabel uint32
	DstID    uint32
	Ifindex  uint32
	// data
}

var obsPoints = map[uint8]string{
	0: "To endpoint",
	1: "To proxy",
	2: "To host",
	3: "To stack",
}

func obsPoint(obsPoint uint8) string {
	if str, ok := obsPoints[obsPoint]; ok {
		return str
	}
	return fmt.Sprintf("%d", obsPoint)
}

// DumpInfo prints a summary of the trace messages.
func (n *TraceNotify) DumpInfo(data []byte) {
	fmt.Printf("xx forward (%s) to endpoint %d, identity %d->%d: %s\n",
		obsPoint(n.ObsPoint), n.DstID, n.SrcLabel, n.DstLabel,
		GetConnectionSummary(data[TraceNotifyLen:]))
}

// DumpVerbose prints the trace notification in human readable form
func (n *TraceNotify) DumpVerbose(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d Packet forwarded %d (%s) %d bytes ifindex=%d",
		prefix, n.Hash, n.Source, n.ObsPoint, obsPoint(n.ObsPoint), n.OrigLen, n.Ifindex)

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		fmt.Printf(" %d->%d", n.SrcLabel, n.DstLabel)
	}

	if n.DstID != 0 {
		fmt.Printf(" to lxc %d\n", n.DstID)
	} else {
		fmt.Printf("\n")
	}

	if n.CapLen > 0 && len(data) > TraceNotifyLen {
		Dissect(dissect, data[TraceNotifyLen:])
	}
}
