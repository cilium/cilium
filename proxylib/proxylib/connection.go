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

package proxylib

import (
	"time"

	"github.com/cilium/cilium/pkg/envoy/cilium"

	log "github.com/sirupsen/logrus"
)

// A parser sees data from the underlying stream in both directions
// (original, connection open direction and the opposite, the reply
// direction). Each call to the filter returns an ordered set of
// operations to be performed on the data in that direction. Any data
// left over after the returned operations must be buffered by the
// caller and passed in again when more data has been received on the
// connection.

type Direction struct {
	InjectBuf *[]byte
}

type Connection struct {
	Instance   *Instance
	Id         uint64
	Ingress    bool
	SrcId      uint32
	DstId      uint32
	SrcAddr    string
	DstAddr    string
	PolicyName string
	Port       uint32

	Parser Parser
	Orig   Direction
	Reply  Direction
}

func (connection *Connection) Matches(l7 interface{}) bool {
	log.Debugf("proxylib: Matching policy on connection %v", connection)
	return connection.Instance.PolicyMatches(connection.PolicyName, connection.Ingress, connection.Port, connection.SrcId, l7)
}

// getInjectBuf return the pointer to the inject buffer slice header for the indicated direction
func (connection *Connection) getInjectBuf(reply bool) *[]byte {
	if reply {
		return connection.Reply.InjectBuf
	}
	return connection.Orig.InjectBuf
}

// inject buffers data to be injected into the connection at the point of INJECT
func (connection *Connection) Inject(reply bool, data []byte) int {
	buf := connection.getInjectBuf(reply)
	// append data to C-provided buffer
	offset := len(*buf)
	n := copy((*buf)[offset:cap(*buf)], data)
	*buf = (*buf)[:offset+n] // update the buffer length

	log.Debugf("proxylib: Injected %d bytes: %s (given: %s)", n, string((*buf)[offset:offset+n]), string(data))

	// return the number of bytes injected. This may be less than the length of `data` is
	// the buffer becomes full.
	// Parser may opt dropping the connection via parser error in this case!
	return n
}

// isInjectBufFull return true if the inject buffer for the indicated direction is full
func (connection *Connection) IsInjectBufFull(reply bool) bool {
	buf := connection.getInjectBuf(reply)
	return len(*buf) == cap(*buf)
}

func (conn *Connection) Log(entryType cilium.EntryType, l7 interface{}) {
	pblog := &cilium.LogEntry{
		Timestamp:             uint64(time.Now().UnixNano()),
		IsIngress:             conn.Ingress,
		EntryType:             entryType,
		PolicyName:            conn.PolicyName,
		SourceSecurityId:      conn.SrcId,
		DestinationSecurityId: conn.DstId,
		SourceAddress:         conn.SrcAddr,
		DestinationAddress:    conn.DstAddr,
		L7:                    cilium.IsL7(l7),
	}
	conn.Instance.Log(pblog)
}
