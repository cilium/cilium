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

package payload

import (
	"bytes"
	"encoding/gob"

	log "github.com/Sirupsen/logrus"
)

// Below constants are based on the ones from <linux/perf_event.h>.
const (
	// EventSample is equivalent to PERF_RECORD_SAMPLE
	EventSample = 9
	// RecordLost is equivalent to PERF_RECORD_LOST
	RecordLost = 2
)

// Meta is used by readers to get information about the payload.
type Meta struct {
	Size uint32
	_    [28]byte // Reserved 28 bytes for future fields.
}

// Payload is the structure used when copying events from the main monitor.
type Payload struct {
	Data []byte
	CPU  int
	Lost uint64
	Type int
}

// Decode decodes a payload from byte array.
func Decode(buf []byte) (*Payload, error) {
	dec := gob.NewDecoder(bytes.NewBuffer(buf))
	var pl Payload
	if err := dec.Decode(&pl); err != nil {
		return &pl, err
	}
	return &pl, nil
}

// Encode prepares a payload to be copied to a queue.
func (pl *Payload) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(pl); err != nil {
		log.Fatal("encode: ", err)
	}
	return buf.Bytes()
}
