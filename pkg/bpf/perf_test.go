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

package bpf

import (
	"time"
	"unsafe"

	. "gopkg.in/check.v1"
)

func (s *BPFTestSuite) TestPerfRead(c *C) {
	var buf [256]byte
	var state [128]byte

	var checkSet int

	var x ReceiveFunc = func(msg *PerfEventSample, cpu int) {}
	var y LostFunc = func(msg *PerfEventLost, cpu int) {}
	var z ErrorFunc = func(msg *PerfEvent) { checkSet = 666 }

	// nonsensical perf event which only aim is to loop PerfEvent.Read
	event := PerfEvent{
		cpu:      1,
		Fd:       1,
		pagesize: 8,
		npages:   5,
		lost:     0,
		unknown:  0,
		buf:      buf,
		state:    unsafe.Pointer(&state[0]),
	}

	event.data = getTestHeader()

	readDone := make(chan struct{})

	go func() {
		event.Read(x, y, z)
		readDone <- struct{}{}
	}()

	select {
	case <-readDone:
		break
	case <-time.After(22 * time.Second):
		c.Assert(false, Equals, true)
	}

	c.Assert(checkSet, Equals, 666)
}
