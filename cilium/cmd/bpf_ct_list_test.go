// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type BPFCtListSuite struct{}

var _ = Suite(&BPFCtListSuite{})

var (
	ctKey4 = ctmap.CtKey4{
		TupleKey4: tuple.TupleKey4{
			DestAddr:   types.IPv4{10, 10, 10, 1},
			SourceAddr: types.IPv4{10, 10, 10, 2},
			DestPort:   byteorder.HostToNetwork(uint16(80)).(uint16),
			SourcePort: byteorder.HostToNetwork(uint16(13579)).(uint16),
			NextHeader: 6,
			Flags:      123,
		},
	}
	ctKey6 = ctmap.CtKey6{
		TupleKey6: tuple.TupleKey6{
			DestAddr:   types.IPv6{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			SourceAddr: types.IPv6{1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61},
			DestPort:   byteorder.HostToNetwork(uint16(443)).(uint16),
			SourcePort: byteorder.HostToNetwork(uint16(7878)).(uint16),
			NextHeader: 17,
			Flags:      31,
		},
	}
	ctValue = ctmap.CtEntry{
		RxPackets:        1,
		RxBytes:          512,
		TxPackets:        4,
		TxBytes:          2048,
		Lifetime:         12345,
		Flags:            3,
		RevNAT:           byteorder.HostToNetwork(uint16(27)).(uint16),
		TxFlagsSeen:      88,
		RxFlagsSeen:      99,
		SourceSecurityID: 6789,
		LastTxReport:     0,
		LastRxReport:     7777,
	}
)

type ctRecord4 struct {
	Key   tuple.TupleKey4
	Value ctmap.CtEntry
}

type ctRecord6 struct {
	Key   tuple.TupleKey6
	Value ctmap.CtEntry
}

type dumpCallback func(maps []interface{}, args ...interface{})

func dumpAndRead(maps []interface{}, dump dumpCallback, c *C, args ...interface{}) string {
	// dumpCt() prints to standard output. Let's redirect it to a pipe, and
	// read the dump from there.
	stdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	c.Assert(err, IsNil, Commentf("failed to create pipe: '%s'", err))
	os.Stdout = writeEnd
	defer func() { os.Stdout = stdout }()

	command.ForceJSON()
	dump(maps, args)

	channel := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, err = io.Copy(&buf, readEnd)
		channel <- buf.String()
	}()

	writeEnd.Close()
	// Even though we have a defer, restore os.Stdout already if we can
	// (for the assert)
	os.Stdout = stdout
	rawDump := <-channel
	c.Assert(err, IsNil, Commentf("failed to read data: '%s'", err))

	return rawDump
}

func (s *BPFCtListSuite) TestDumpCt4(c *C) {

	ctMaps := [2]ctmap.CtMap{
		ctmap.NewCtMockMap(
			[]ctmap.CtMapRecord{
				{
					Key:   &ctKey4,
					Value: ctValue,
				},
				{
					Key:   &ctKey4,
					Value: ctValue,
				},
			},
		),
		ctmap.NewCtMockMap(
			[]ctmap.CtMapRecord{
				{
					Key:   &ctKey4,
					Value: ctValue,
				},
			},
		),
	}

	maps := make([]interface{}, len(ctMaps))
	for i, m := range ctMaps {
		maps[i] = m
	}
	rawDump := dumpAndRead(maps, dumpCt, c, "")

	var ctDump []ctRecord4
	err := json.Unmarshal([]byte(rawDump), &ctDump)
	c.Assert(err, IsNil, Commentf("invalid JSON output: '%s', '%s'", err, rawDump))

	// JSON output may reorder the entries, but in our case they are all
	// the same.
	ctRecordDump := ctmap.CtMapRecord{
		Key:   &ctmap.CtKey4{TupleKey4: ctDump[0].Key},
		Value: ctDump[0].Value,
	}
	c.Assert(ctRecordDump, checker.DeepEquals, ctMaps[0].(*ctmap.CtMockMap).Entries[0])
}

func (s *BPFCtListSuite) TestDumpCt6(c *C) {

	ctMaps := [2]ctmap.CtMap{
		ctmap.NewCtMockMap(
			[]ctmap.CtMapRecord{
				{
					Key:   &ctKey6,
					Value: ctValue,
				},
				{
					Key:   &ctKey6,
					Value: ctValue,
				},
			},
		),
		ctmap.NewCtMockMap(
			[]ctmap.CtMapRecord{
				{
					Key:   &ctKey6,
					Value: ctValue,
				},
			},
		),
	}

	maps := make([]interface{}, len(ctMaps))
	for i, m := range ctMaps {
		maps[i] = m
	}
	rawDump := dumpAndRead(maps, dumpCt, c, "")

	var ctDump []ctRecord6
	err := json.Unmarshal([]byte(rawDump), &ctDump)
	c.Assert(err, IsNil, Commentf("invalid JSON output: '%s', '%s'", err, rawDump))

	// JSON output may reorder the entries, but in our case they are all
	// the same.
	ctRecordDump := ctmap.CtMapRecord{
		Key:   &ctmap.CtKey6{TupleKey6: ctDump[0].Key},
		Value: ctDump[0].Value,
	}
	c.Assert(ctRecordDump, checker.DeepEquals, ctMaps[0].(*ctmap.CtMockMap).Entries[0])
}
