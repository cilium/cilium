// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package payload

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
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
