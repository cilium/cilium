// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pcap

import (
	"io"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/byteorder"
)

// Datalink defines the type of the first layer of the captured packet
type Datalink uint32

var (
	Null     Datalink = 0
	Ethernet Datalink = 1
)

const (
	MagicNumber  = 0xa1b2c3d4
	VersionMajor = 2
	VersionMinor = 4

	TimestampCorrection = 0
	TimestampAccuracy   = 0

	DefaultSnapLen = 65535
)

const (
	GlobalHeaderByteLen = 24
	RecordHeaderByteLen = 16
)

// Header contains the configurable parameters for the global pcap header
type Header struct {
	// SnapshotLength is the maximum length of captured packets
	SnapshotLength uint32
	// Datalink is the type of header at the beginning of the packet
	Datalink Datalink
}

// Bytes returns the byte representation of the global pcap header
func (h *Header) Bytes() []byte {
	// https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
	const (
		offsetMagicNumber         = 0
		offsetVersionMajor        = 4
		offsetVersionMinor        = 6
		offsetTimestampCorrection = 8
		offsetTimestampAccuracy   = 12
		offsetSnapshotLength      = 16
		offsetDatalink            = 20
	)

	native := byteorder.Native
	b := make([]byte, GlobalHeaderByteLen)

	snapLen := h.SnapshotLength
	if snapLen == 0 {
		snapLen = DefaultSnapLen
	}

	native.PutUint32(b[offsetMagicNumber:], MagicNumber)
	native.PutUint16(b[offsetVersionMajor:], VersionMajor)
	native.PutUint16(b[offsetVersionMinor:], VersionMinor)
	native.PutUint32(b[offsetTimestampCorrection:], TimestampCorrection)
	native.PutUint32(b[offsetTimestampAccuracy:], TimestampAccuracy)
	native.PutUint32(b[offsetSnapshotLength:], snapLen)
	native.PutUint32(b[offsetDatalink:], uint32(h.Datalink))

	return b
}

// Record contains the configurable parameters for a record header
type Record struct {
	// Timestamp is the time the packet was captured
	Timestamp time.Time
	// CaptureLength is the size of the captured packet
	CaptureLength uint32
	// OriginalLength is the size of the original packet
	OriginalLength uint32
}

// Bytes returns the byte representation of the per-record pcap header
func (r *Record) Bytes() []byte {
	// https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
	const (
		offsetTimestampUnix   = 0
		offsetTimestampMicros = 4
		offsetCaptureLength   = 8
		offsetOriginalLength  = 12
	)

	tsUnix := uint32(r.Timestamp.Unix())
	tsMicros := uint32(r.Timestamp.Nanosecond() / 1000)

	native := byteorder.Native
	b := make([]byte, RecordHeaderByteLen)

	native.PutUint32(b[offsetTimestampUnix:], tsUnix)
	native.PutUint32(b[offsetTimestampMicros:], tsMicros)
	native.PutUint32(b[offsetCaptureLength:], r.CaptureLength)
	native.PutUint32(b[offsetOriginalLength:], r.OriginalLength)

	return b
}

// RecordWriter defines the interface for pcap writers
type RecordWriter interface {
	// WriteHeader writes the global pcap header. This must be invoked before
	// WriteRecord is called.
	WriteHeader(header Header) error
	// WriteRecord writes a pcap record to the underlying stream.
	WriteRecord(record Record, packet []byte) error
	io.Closer
}

var _ RecordWriter = (*Writer)(nil)

// Writer wraps a io.WriteCloser to implement RecordWriter
type Writer struct {
	io.WriteCloser
}

// NewWriter wraps a io.WriteCloser
func NewWriter(w io.WriteCloser) *Writer {
	return &Writer{
		WriteCloser: w,
	}
}

// WriteHeader implements RecordWriter
func (w *Writer) WriteHeader(header Header) error {
	_, err := w.Write(header.Bytes())
	return err
}

// WriteRecord implements RecordWriter
func (w *Writer) WriteRecord(record Record, packet []byte) error {
	ioVec := net.Buffers{record.Bytes(), packet}
	_, err := ioVec.WriteTo(w)
	return err
}
