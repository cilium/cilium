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
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/byteorder"
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

// UnmarshalBinary decodes the metadata from its binary representation.
func (meta *Meta) UnmarshalBinary(data []byte) error {
	return meta.ReadBinary(bytes.NewReader(data))
}

// MarshalBinary encodes the metadata into its binary representation.
func (meta *Meta) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if err := meta.WriteBinary(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadBinary reads the metadata from its binary representation.
func (meta *Meta) ReadBinary(r io.Reader) error {
	return binary.Read(r, byteorder.Native, meta)
}

// WriteBinary writes the metadata into its binary representation.
func (meta *Meta) WriteBinary(w io.Writer) error {
	return binary.Write(w, byteorder.Native, meta)
}

// Payload is the structure used when copying events from the main monitor.
type Payload struct {
	Data []byte
	CPU  int
	Lost uint64
	Type int
}

// Decode decodes the payload from its binary representation.
func (pl *Payload) Decode(data []byte) error {
	// Note that this method can't be named UnmarshalBinary, because the gob encoder would call
	// this method, resulting in infinite recursion.
	return pl.ReadBinary(bytes.NewBuffer(data))
}

// Encode encodes the payload into its binary representation.
func (pl *Payload) Encode() ([]byte, error) {
	// Note that this method can't be named MarshalBinary, because the gob encoder would call
	// this method, resulting in infinite recursion.
	var buf bytes.Buffer
	if err := pl.WriteBinary(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadBinary reads the payload from its binary representation.
func (pl *Payload) ReadBinary(r io.Reader) error {
	dec := gob.NewDecoder(r)
	return pl.DecodeBinary(dec)
}

// WriteBinary writes the payload into its binary representation.
func (pl *Payload) WriteBinary(w io.Writer) error {
	enc := gob.NewEncoder(w)
	return pl.EncodeBinary(enc)
}

// EncodeBinary writes the payload into its binary representation.
func (pl *Payload) EncodeBinary(enc *gob.Encoder) error {
	return enc.Encode(pl)
}

// DecodeBinary reads the payload from its binary representation.
func (pl *Payload) DecodeBinary(dec *gob.Decoder) error {
	return dec.Decode(pl)
}

// ReadMetaPayload reads a Meta and Payload from a Cilium monitor connection.
func ReadMetaPayload(r io.Reader, meta *Meta, pl *Payload) error {
	if err := meta.ReadBinary(r); err != nil {
		return err
	}

	// Meta.Size is not necessary for framing/decoding, but is useful to validate the payload size.
	return pl.ReadBinary(io.LimitReader(r, int64(meta.Size)))
}

// WriteMetaPayload writes a Meta and Payload into a Cilium monitor connection.
// meta.Size is set to the size of the encoded Payload.
func WriteMetaPayload(w io.Writer, meta *Meta, pl *Payload) error {
	payloadBuf, err := pl.Encode()
	if err != nil {
		return err
	}
	meta.Size = uint32(len(payloadBuf))
	meta.WriteBinary(w)
	_, err = w.Write(payloadBuf)
	return err
}

// BuildMessage builds the binary message to be sent and returns it
func (pl *Payload) BuildMessage() ([]byte, error) {
	plBuf, err := pl.Encode()
	if err != nil {
		return nil, fmt.Errorf("unable to encode payload: %s", err)
	}

	meta := &Meta{Size: uint32(len(plBuf))}
	metaBuf, err := meta.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to encode metadata: %s", err)
	}

	return append(metaBuf, plBuf...), nil
}
