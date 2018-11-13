package proto

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"time"

	"github.com/golang/snappy"
)

/*

Kafka wire protocol implemented as described in http://kafka.apache.org/protocol.html

*/

const (
	KafkaV0 int16 = iota
	KafkaV1
	KafkaV2
	KafkaV3
	KafkaV4
	KafkaV5
)

const (
	ProduceReqKind          = 0
	FetchReqKind            = 1
	OffsetReqKind           = 2
	MetadataReqKind         = 3
	OffsetCommitReqKind     = 8
	OffsetFetchReqKind      = 9
	ConsumerMetadataReqKind = 10
	APIVersionsReqKind      = 18
	CreateTopicsReqKind     = 19
)

const (

	// receive the latest offset (i.e. the offset of the next coming message)
	OffsetReqTimeLatest = -1

	// receive the earliest available offset. Note that because offsets are
	// pulled in descending order, asking for the earliest offset will always
	// return you a single element.
	OffsetReqTimeEarliest = -2

	// Server will not send any response.
	RequiredAcksNone = 0

	// Server will block until the message is committed by all in sync replicas
	// before sending a response.
	RequiredAcksAll = -1

	// Server will wait the data is written to the local log before sending a
	// response.
	RequiredAcksLocal = 1
)

type Request interface {
	Kind() int16
	GetHeader() *RequestHeader
	GetVersion() int16
	GetCorrelationID() int32
	GetClientID() string
	SetClientID(cliendID string)
	io.WriterTo
	Bytes() ([]byte, error)
}

var _ Request = &ProduceReq{}
var _ Request = &FetchReq{}
var _ Request = &OffsetReq{}
var _ Request = &MetadataReq{}
var _ Request = &OffsetCommitReq{}
var _ Request = &OffsetFetchReq{}
var _ Request = &ConsumerMetadataReq{}
var _ Request = &APIVersionsReq{}
var _ Request = &CreateTopicsReq{}

func SetVersion(header *RequestHeader, version int16) {
	header.version = version
}

func SetCorrelationID(header *RequestHeader, correlationID int32) {
	header.correlationID = correlationID
}

type RequestHeader struct {
	version       int16
	correlationID int32
	ClientID      string
}

func (h *RequestHeader) GetHeader() *RequestHeader {
	return h
}

func (h *RequestHeader) GetVersion() int16 {
	return h.version
}

func (h *RequestHeader) GetCorrelationID() int32 {
	return h.correlationID
}

func (h *RequestHeader) GetClientID() string {
	return h.ClientID
}

func (h *RequestHeader) SetClientID(cliendID string) {
	h.ClientID = cliendID
}

var SupportedByDriver = map[int16]SupportedVersion{
	ProduceReqKind:          SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV2},
	FetchReqKind:            SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV5},
	OffsetReqKind:           SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV2},
	MetadataReqKind:         SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV5},
	OffsetCommitReqKind:     SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV3},
	OffsetFetchReqKind:      SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV3},
	ConsumerMetadataReqKind: SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV1},
	APIVersionsReqKind:      SupportedVersion{MinVersion: KafkaV0, MaxVersion: KafkaV1},
}

type Compression int8

const (
	CompressionNone   Compression = 0
	CompressionGzip   Compression = 1
	CompressionSnappy Compression = 2
)

// ParserConfig is optional configuration for the parser. It can be configured via
// SetParserConfig
type ParserConfig struct {
	// SimplifiedMessageSetParsing enables a simplified version of the
	// MessageSet parser which will not split MessageSet into slices of
	// Message structures. Instead, the entire MessageSet will be read
	// over. This mode improves parsing speed due to reduce memory read at
	// the cost of not providing access to the message payload after
	// parsing.
	SimplifiedMessageSetParsing bool
}

var (
	conf ParserConfig
)

// ConfigureParser configures the parser. It must be called prior to parsing
// any messages as the structure is currently not prepared for concurrent
// access.
func ConfigureParser(c ParserConfig) error {
	conf = c
	return nil
}

func boolToInt8(val bool) int8 {
	res := int8(0)
	if val {
		res = 1
	}
	return res
}

// ReadReq returns request kind ID and byte representation of the whole message
// in wire protocol format.
func ReadReq(r io.Reader) (requestKind int16, b []byte, err error) {
	dec := NewDecoder(r)
	msgSize := dec.DecodeInt32()
	requestKind = dec.DecodeInt16()
	if err := dec.Err(); err != nil {
		return 0, nil, err
	}
	// size of the message + size of the message itself
	b, err = allocParseBuf(int(msgSize + 4))
	if err != nil {
		return 0, nil, err
	}

	binary.BigEndian.PutUint32(b, uint32(msgSize))

	// only write back requestKind if it was included in messageSize
	if len(b) >= 6 {
		binary.BigEndian.PutUint16(b[4:], uint16(requestKind))
	}

	// read rest of request into allocated buffer if we allocated for it
	if len(b) > 6 {
		if _, err := io.ReadFull(r, b[6:]); err != nil {
			return 0, nil, err
		}
	}

	return requestKind, b, nil
}

// ReadResp returns message correlation ID and byte representation of the whole
// message in wire protocol that is returned when reading from given stream,
// including 4 bytes of message size itself.
// Byte representation returned by ReadResp can be parsed by all response
// reeaders to transform it into specialized response structure.
func ReadResp(r io.Reader) (correlationID int32, b []byte, err error) {
	dec := NewDecoder(r)
	msgSize := dec.DecodeInt32()
	correlationID = dec.DecodeInt32()
	if err := dec.Err(); err != nil {
		return 0, nil, err
	}
	// size of the message + size of the message itself
	b, err = allocParseBuf(int(msgSize + 4))
	if err != nil {
		return 0, nil, err
	}

	binary.BigEndian.PutUint32(b, uint32(msgSize))
	binary.BigEndian.PutUint32(b[4:], uint32(correlationID))
	_, err = io.ReadFull(r, b[8:])
	return correlationID, b, err
}

// Message represents single entity of message set.
type Message struct {
	Key       []byte
	Value     []byte
	Offset    int64  // set when fetching and after successful producing
	Crc       uint32 // set when fetching, ignored when producing
	Topic     string // set when fetching, ignored when producing
	Partition int32  // set when fetching, ignored when producing
	TipOffset int64  // set when fetching, ignored when processing
}

// ComputeCrc returns crc32 hash for given message content.
func ComputeCrc(m *Message, compression Compression) uint32 {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	enc.EncodeInt8(0) // magic byte is always 0
	enc.EncodeInt8(int8(compression))
	enc.EncodeBytes(m.Key)
	enc.EncodeBytes(m.Value)
	return crc32.ChecksumIEEE(buf.Bytes())
}

// writeMessageSet writes a Message Set into w.
// It returns the number of bytes written and any error.
func writeMessageSet(w io.Writer, messages []*Message, compression Compression) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	// NOTE(caleb): it doesn't appear to be documented, but I observed that the
	// Java client sets the offset of the synthesized message set for a group of
	// compressed messages to be the offset of the last message in the set.
	compressOffset := messages[len(messages)-1].Offset
	switch compression {
	case CompressionGzip:
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := writeMessageSet(gz, messages, CompressionNone); err != nil {
			return 0, err
		}
		if err := gz.Close(); err != nil {
			return 0, err
		}
		messages = []*Message{
			{
				Value:  buf.Bytes(),
				Offset: compressOffset,
			},
		}
	case CompressionSnappy:
		var buf bytes.Buffer
		if _, err := writeMessageSet(&buf, messages, CompressionNone); err != nil {
			return 0, err
		}
		messages = []*Message{
			{
				Value:  snappy.Encode(nil, buf.Bytes()),
				Offset: compressOffset,
			},
		}
	}

	totalSize := 0
	b, err := newSliceWriter(0)
	if err != nil {
		return 0, err
	}

	for _, message := range messages {
		bsize := 26 + len(message.Key) + len(message.Value)
		if err := b.Reset(bsize); err != nil {
			return 0, err
		}

		enc := NewEncoder(b)
		enc.EncodeInt64(message.Offset)
		msize := int32(14 + len(message.Key) + len(message.Value))
		enc.EncodeInt32(msize)
		enc.EncodeUint32(0) // crc32 placeholder
		enc.EncodeInt8(0)   // magic byte
		enc.EncodeInt8(int8(compression))
		enc.EncodeBytes(message.Key)
		enc.EncodeBytes(message.Value)

		if err := enc.Err(); err != nil {
			return totalSize, err
		}

		const hsize = 8 + 4 + 4 // offset + message size + crc32
		const crcoff = 8 + 4    // offset + message size
		binary.BigEndian.PutUint32(b.buf[crcoff:crcoff+4], crc32.ChecksumIEEE(b.buf[hsize:bsize]))

		if n, err := w.Write(b.Slice()); err != nil {
			return totalSize, err
		} else {
			totalSize += n
		}

	}
	return totalSize, nil
}

type slicewriter struct {
	buf  []byte
	pos  int
	size int
}

func newSliceWriter(bufsize int) (*slicewriter, error) {
	buf, err := allocParseBuf(bufsize)
	if err != nil {
		return nil, err
	}

	return &slicewriter{
		buf: buf,
		pos: 0,
	}, nil
}

func (w *slicewriter) Write(p []byte) (int, error) {
	if len(w.buf) < w.pos+len(p) {
		return 0, errors.New("buffer too small")
	}
	copy(w.buf[w.pos:], p)
	w.pos += len(p)
	return len(p), nil
}

func (w *slicewriter) Reset(size int) error {
	if size > len(w.buf) {
		var err error

		w.buf, err = allocParseBuf(size + 1000) // allocate a bit more than required
		if err != nil {
			return err
		}
	}
	w.size = size
	w.pos = 0
	return nil
}

func (w *slicewriter) Slice() []byte {
	return w.buf[:w.pos]
}

// readRecordBatch reasd and return record batch from the stream
// RecordBatch replace MessageSet for kafka >= 0.11

// Because kafka is sending message set directly from the drive, it might cut
// off part of the last message. This also means that the last message can be
// shorter than the header is saying. In such case just ignore the last
// malformed message from the set and returned earlier data.
func readRecordBatch(r io.Reader, size int32) (*RecordBatch, error) {
	rd := io.LimitReader(r, int64(size))
	dec := NewDecoder(rd)

	rb := &RecordBatch{}
	rb.FirstOffset = dec.DecodeInt64()
	rb.Length = dec.DecodeInt32()
	rb.PartitionLeaderEpoch = dec.DecodeInt32()

	// Magic byte. It represents a version of a message.
	// But we've already determinated that this is a record batch
	// and since there is only one version of record batch exists, we can just ignore it.
	_ = dec.DecodeInt8()

	rb.CRC = dec.DecodeInt32()

	crc := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	r = io.TeeReader(rd, crc)
	dec = NewDecoder(r)

	rb.Attributes = dec.DecodeInt16()
	rb.LastOffsetDelta = dec.DecodeInt32()

	rb.FirstTimestamp = dec.DecodeInt64()
	rb.MaxTimestamp = dec.DecodeInt64()
	rb.ProducerId = dec.DecodeInt64()
	rb.ProducerEpoch = dec.DecodeInt16()
	rb.FirstSequence = dec.DecodeInt32()

	slen, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}

	switch rb.Compression() {
	case CompressionNone:
		break
	case CompressionGzip:
		r, err = gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		allUnzipped, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(allUnzipped)

	case CompressionSnappy:
		var err error
		val, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		decoded, err := snappyDecode(val)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(decoded)
	default:
		return nil, errors.New("Unknown compression")
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}

	rb.Records = make([]*Record, 0, slen)

	for i := 0; i < slen; i++ {
		rec, err := readRecord(r)
		if (err == ErrNotEnoughData || err == io.EOF || err == io.ErrUnexpectedEOF) && len(rb.Records) > 0 {
			// Think that it was partial record and we just ignore it
			return rb, nil
		}
		if err != nil {
			return nil, err
		}
		rb.Records = append(rb.Records, rec)
	}
	if uint32(rb.CRC) != crc.Sum32() {
		return nil, fmt.Errorf("Wrong CRC32")
	}
	return rb, nil
}

func readRecord(r io.Reader) (*Record, error) {
	dec := NewDecoder(r)
	rec := &Record{}
	rec.Length = dec.DecodeVarInt()
	rec.Attributes = dec.DecodeInt8()
	rec.TimestampDelta = dec.DecodeVarInt()
	rec.OffsetDelta = dec.DecodeVarInt()

	rec.Key = dec.DecodeVarBytes()
	rec.Value = dec.DecodeVarBytes()

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}

	rec.Headers = make([]RecordHeader, len)
	for i := range rec.Headers {
		rec.Headers[i].Key = dec.DecodeVarString()
		rec.Headers[i].Value = dec.DecodeVarBytes()
	}
	return rec, nil
}

// readMessageSet reads and return messages from the stream.
// The size is known before a message set is decoded.
// Because kafka is sending message set directly from the drive, it might cut
// off part of the last message. This also means that the last message can be
// shorter than the header is saying. In such case just ignore the last
// malformed message from the set and returned earlier data.
func readMessageSet(r io.Reader, size int32) ([]*Message, error) {
	if size < 0 || size > maxParseBufSize {
		return nil, messageSizeError(int(size))
	}

	rd := io.LimitReader(r, int64(size))

	if conf.SimplifiedMessageSetParsing {
		msgbuf, err := allocParseBuf(int(size))
		if err != nil {
			return nil, err
		}

		if _, err := io.ReadFull(rd, msgbuf); err != nil {
			return nil, err
		}
		return make([]*Message, 0, 0), nil
	}

	dec := NewDecoder(rd)
	set := make([]*Message, 0, 256)

	for {
		offset := dec.DecodeInt64()
		if err := dec.Err(); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return set, nil
			}
			return nil, err
		}
		// single message size
		size := dec.DecodeInt32()
		if err := dec.Err(); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return set, nil
			}
			return nil, err
		}

		// Skip over empty messages
		if size <= int32(0) {
			return set, nil
		}

		msgbuf, err := allocParseBuf(int(size))
		if err != nil {
			return nil, err
		}

		if _, err := io.ReadFull(rd, msgbuf); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return set, nil
			}
			return nil, err
		}
		msgdec := NewDecoder(bytes.NewBuffer(msgbuf))

		msg := &Message{
			Offset: offset,
			Crc:    msgdec.DecodeUint32(),
		}

		// MessageSet with no payload
		if size <= int32(4) {
			set = append(set, msg)
			return set, nil
		}

		if msg.Crc != crc32.ChecksumIEEE(msgbuf[4:]) {
			// ignore this message and because we want to have constant
			// history, do not process anything more
			return set, nil
		}

		// magic byte
		messageVersion := MessageVersion(msgdec.DecodeInt8())

		attributes := msgdec.DecodeInt8()

		if messageVersion == MessageV1 {
			// timestamp
			_ = msgdec.DecodeInt64()
		}

		switch compression := Compression(attributes & 3); compression {
		case CompressionNone:
			msg.Key = msgdec.DecodeBytes()
			msg.Value = msgdec.DecodeBytes()
			if err := msgdec.Err(); err != nil {
				return nil, err
			}
			set = append(set, msg)
		case CompressionGzip, CompressionSnappy:
			_ = msgdec.DecodeBytes() // ignore key
			val := msgdec.DecodeBytes()
			if err := msgdec.Err(); err != nil {
				return nil, err
			}
			var decoded []byte
			switch compression {
			case CompressionGzip:
				cr, err := gzip.NewReader(bytes.NewReader(val))
				if err != nil {
					return nil, err
				}
				decoded, err = ioutil.ReadAll(cr)
				if err != nil {
					return nil, err
				}
				_ = cr.Close()
			case CompressionSnappy:
				var err error
				decoded, err = snappyDecode(val)
				if err != nil {
					return nil, err
				}
			}
			msgs, err := readMessageSet(bytes.NewReader(decoded), int32(len(decoded)))
			if err != nil {
				return nil, err
			}
			set = append(set, msgs...)
		default:
			return nil, err
		}
	}
}

func encodeHeader(e *encoder, r Request) {
	// message size - for now just placeholder
	e.Encode(int32(0))
	e.Encode(int16(r.Kind()))
	e.Encode(r.GetVersion())
	e.Encode(r.GetCorrelationID())
	e.Encode(r.GetClientID())
}

func decodeHeader(dec *decoder, req Request) {
	// total message size
	_ = dec.DecodeInt32()
	// api key
	_ = dec.DecodeInt16()
	SetVersion(req.GetHeader(), dec.DecodeInt16())
	SetCorrelationID(req.GetHeader(), dec.DecodeInt32())
	req.SetClientID(dec.DecodeString())
}

type MetadataReq struct {
	RequestHeader
	Topics                 []string
	AllowAutoTopicCreation bool // >= KafkaV4 only
}

func ReadMetadataReq(r io.Reader) (*MetadataReq, error) {
	var req MetadataReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.Topics = make([]string, len)

	for i := range req.Topics {
		req.Topics[i] = dec.DecodeString()
	}

	if req.version >= KafkaV4 {
		req.AllowAutoTopicCreation = dec.DecodeInt8() != 0
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r MetadataReq) Kind() int16 {
	return MetadataReqKind
}

func (r *MetadataReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	if len(r.Topics) == 0 {
		if r.version >= 1 {
			enc.EncodeArrayLen(-1)
		} else {
			enc.EncodeArrayLen(0)
		}
	} else {
		enc.EncodeArrayLen(len(r.Topics))
	}
	for _, name := range r.Topics {
		enc.Encode(name)
	}

	if r.version >= KafkaV4 {
		enc.Encode(boolToInt8(r.AllowAutoTopicCreation))
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *MetadataReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type MetadataResp struct {
	Version       int16
	CorrelationID int32
	ThrottleTime  time.Duration // >= KafkaV3
	Brokers       []MetadataRespBroker
	ClusterID     string // >= KafkaV2
	ControllerID  int32  // >= KafkaV1
	Topics        []MetadataRespTopic
}

type MetadataRespBroker struct {
	NodeID int32
	Host   string
	Port   int32
	Rack   string // >= KafkaV1
}

type MetadataRespTopic struct {
	Name       string
	Err        error
	IsInternal bool // >= KafkaV1
	Partitions []MetadataRespPartition
}

type MetadataRespPartition struct {
	Err             error
	ID              int32
	Leader          int32
	Replicas        []int32
	Isrs            []int32
	OfflineReplicas []int32
}

func (r *MetadataResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV3 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeArrayLen(len(r.Brokers))
	for _, broker := range r.Brokers {
		enc.Encode(broker.NodeID)
		enc.Encode(broker.Host)
		enc.Encode(broker.Port)

		if r.Version >= KafkaV1 {
			enc.Encode(broker.Rack)
		}
	}

	if r.Version >= KafkaV2 {
		enc.Encode(r.ClusterID)
	}

	if r.Version >= KafkaV1 {
		enc.Encode(r.ControllerID)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.EncodeError(topic.Err)
		enc.Encode(topic.Name)

		if r.Version >= KafkaV1 {
			enc.Encode(boolToInt8(topic.IsInternal))
		}

		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.EncodeError(part.Err)
			enc.Encode(part.ID)
			enc.Encode(part.Leader)
			enc.Encode(part.Replicas)
			enc.Encode(part.Isrs)
			if r.Version >= KafkaV5 {
				enc.Encode(part.OfflineReplicas)
			}
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func ReadMetadataResp(r io.Reader) (*MetadataResp, error) {
	return ReadVersionedMetadataResp(r, KafkaV0)
}

func ReadVersionedMetadataResp(r io.Reader, version int16) (*MetadataResp, error) {
	var resp MetadataResp
	resp.Version = version
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	if resp.Version >= KafkaV3 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Brokers = make([]MetadataRespBroker, len)

	for i := range resp.Brokers {
		var b = &resp.Brokers[i]
		b.NodeID = dec.DecodeInt32()
		b.Host = dec.DecodeString()
		b.Port = dec.DecodeInt32()
		if resp.Version >= KafkaV1 {
			b.Rack = dec.DecodeString()
		}
	}

	if resp.Version >= KafkaV2 {
		resp.ClusterID = dec.DecodeString()
	}

	if resp.Version >= KafkaV1 {
		resp.ControllerID = dec.DecodeInt32()
	}

	len, err = dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Topics = make([]MetadataRespTopic, len)

	for ti := range resp.Topics {
		var t = &resp.Topics[ti]
		t.Err = errFromNo(dec.DecodeInt16())
		t.Name = dec.DecodeString()

		if resp.Version >= KafkaV1 {
			t.IsInternal = (dec.DecodeInt8() == 1)
		}

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		t.Partitions = make([]MetadataRespPartition, len)

		for pi := range t.Partitions {
			var p = &t.Partitions[pi]
			p.Err = errFromNo(dec.DecodeInt16())
			p.ID = dec.DecodeInt32()
			p.Leader = dec.DecodeInt32()

			len, err = dec.DecodeArrayLen()
			if err != nil {
				return nil, err
			}
			p.Replicas = make([]int32, len)

			for ri := range p.Replicas {
				p.Replicas[ri] = dec.DecodeInt32()
			}

			len, err = dec.DecodeArrayLen()
			if err != nil {
				return nil, err
			}
			p.Isrs = make([]int32, len)

			for ii := range p.Isrs {
				p.Isrs[ii] = dec.DecodeInt32()
			}

			if resp.Version >= KafkaV5 {
				len, err = dec.DecodeArrayLen()
				if err != nil {
					return nil, err
				}
				p.OfflineReplicas = make([]int32, len)

				for ii := range p.OfflineReplicas {
					p.OfflineReplicas[ii] = dec.DecodeInt32()
				}
			}
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &resp, nil
}

type FetchReq struct {
	RequestHeader
	ReplicaID      int32
	MaxWaitTime    time.Duration
	MinBytes       int32
	MaxBytes       int32 // >= KafkaV3
	IsolationLevel int8  // >= KafkaV4

	Topics []FetchReqTopic
}

type FetchReqTopic struct {
	Name       string
	Partitions []FetchReqPartition
}

type FetchReqPartition struct {
	ID             int32
	FetchOffset    int64
	LogStartOffset int64 // >= KafkaV5
	MaxBytes       int32
}

func ReadFetchReq(r io.Reader) (*FetchReq, error) {
	var req FetchReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	req.ReplicaID = dec.DecodeInt32()
	req.MaxWaitTime = dec.DecodeDuration32()
	req.MinBytes = dec.DecodeInt32()

	if req.version >= KafkaV3 {
		req.MaxBytes = dec.DecodeInt32()
	}

	if req.version >= KafkaV4 {
		req.IsolationLevel = dec.DecodeInt8()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.Topics = make([]FetchReqTopic, len)

	for ti := range req.Topics {
		var topic = &req.Topics[ti]
		topic.Name = dec.DecodeString()

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		topic.Partitions = make([]FetchReqPartition, len)

		for pi := range topic.Partitions {
			var part = &topic.Partitions[pi]
			part.ID = dec.DecodeInt32()
			part.FetchOffset = dec.DecodeInt64()

			if req.version >= KafkaV5 {
				part.LogStartOffset = dec.DecodeInt64()
			}

			part.MaxBytes = dec.DecodeInt32()
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r FetchReq) Kind() int16 {
	return FetchReqKind
}

func (r *FetchReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	//enc.Encode(r.ReplicaID)
	enc.Encode(int32(-1))

	enc.Encode(r.MaxWaitTime)
	enc.Encode(r.MinBytes)

	if r.version >= KafkaV3 {
		enc.Encode(r.MaxBytes)
	}

	if r.version >= KafkaV4 {
		enc.Encode(r.IsolationLevel)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.Encode(part.FetchOffset)

			if r.version >= KafkaV5 {
				enc.Encode(part.LogStartOffset)
			}

			enc.Encode(part.MaxBytes)
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *FetchReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type FetchResp struct {
	Version       int16
	CorrelationID int32
	ThrottleTime  time.Duration
	Topics        []FetchRespTopic
}

type FetchRespTopic struct {
	Name       string
	Partitions []FetchRespPartition
}

// Message version define which format of messages
// is using in this particular Produce/Response
// MessageV0  and MessageV1 indicate usage of MessageSet
// MessageV3 indicate usage of RecordBatch
// See https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol#AGuideToTheKafkaProtocol-Messagesets
type MessageVersion int8

const MessageV0 MessageVersion = 0
const MessageV1 MessageVersion = 1
const MessageV2 MessageVersion = 2

type FetchRespPartition struct {
	ID                  int32
	Err                 error
	TipOffset           int64
	LastStableOffset    int64
	LogStartOffset      int64
	AbortedTransactions []FetchRespAbortedTransaction
	Messages            []*Message
	MessageVersion      MessageVersion
	RecordBatch         *RecordBatch
}

type FetchRespAbortedTransaction struct {
	ProducerID  int64
	FirstOffset int64
}

type RecordBatch struct {
	FirstOffset          int64
	Length               int32
	PartitionLeaderEpoch int32
	Magic                int8
	CRC                  int32
	Attributes           int16
	LastOffsetDelta      int32
	FirstTimestamp       int64
	MaxTimestamp         int64
	ProducerId           int64
	ProducerEpoch        int16
	FirstSequence        int32
	Records              []*Record
}

type Record struct {
	Length         int64
	Attributes     int8
	TimestampDelta int64
	OffsetDelta    int64
	Key            []byte
	Value          []byte
	Headers        []RecordHeader
}

type RecordHeader struct {
	Key   string
	Value []byte
}

func (rb *RecordBatch) Compression() Compression {
	return Compression(rb.Attributes & 3)
}

func (r *FetchResp) Bytes() ([]byte, error) {
	var buf buffer
	enc := NewEncoder(&buf)

	enc.Encode(int32(0)) // placeholder
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV1 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.EncodeError(part.Err)
			enc.Encode(part.TipOffset)

			if r.Version >= KafkaV4 {
				enc.Encode(part.LastStableOffset)

				if r.Version >= KafkaV5 {
					enc.Encode(part.LogStartOffset)
				}

				enc.EncodeArrayLen(len(part.AbortedTransactions))
				for _, trans := range part.AbortedTransactions {
					enc.Encode(trans.ProducerID)
					enc.Encode(trans.FirstOffset)
				}
			}

			i := len(buf)
			enc.Encode(int32(0)) // placeholder
			// NOTE(caleb): writing compressed fetch response isn't implemented
			// for now, since that's not needed for clients.
			n, err := writeMessageSet(&buf, part.Messages, CompressionNone)
			if err != nil {
				return nil, err
			}
			binary.BigEndian.PutUint32(buf[i:i+4], uint32(n))
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	binary.BigEndian.PutUint32(buf[:4], uint32(len(buf)-4))
	return []byte(buf), nil
}

func ReadFetchResp(r io.Reader) (*FetchResp, error) {
	return ReadVersionedFetchResp(r, KafkaV0)
}

func ReadVersionedFetchResp(r io.Reader, version int16) (*FetchResp, error) {
	var err error
	var resp FetchResp

	resp.Version = version

	//Have to wrap because we use Peek later
	br := bufio.NewReader(r)
	dec := NewDecoder(br)
	r = nil // just to prevent later usage

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	if resp.Version >= KafkaV1 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Topics = make([]FetchRespTopic, len)

	for ti := range resp.Topics {
		var topic = &resp.Topics[ti]
		topic.Name = dec.DecodeString()

		len, err := dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		topic.Partitions = make([]FetchRespPartition, len)

		for pi := range topic.Partitions {
			var part = &topic.Partitions[pi]
			part.ID = dec.DecodeInt32()
			part.Err = errFromNo(dec.DecodeInt16())
			part.TipOffset = dec.DecodeInt64()

			if resp.Version >= KafkaV4 {
				part.LastStableOffset = dec.DecodeInt64()
				if resp.Version >= KafkaV5 {
					part.LogStartOffset = dec.DecodeInt64()
				}
				len, err := dec.DecodeArrayLen()
				if err != nil {
					return nil, err
				}
				part.AbortedTransactions = make([]FetchRespAbortedTransaction, len)
				for i := range part.AbortedTransactions {
					part.AbortedTransactions[i].ProducerID = dec.DecodeInt64()
					part.AbortedTransactions[i].FirstOffset = dec.DecodeInt64()
				}
			}

			if dec.Err() != nil {
				return nil, dec.Err()
			}
			msgSetSize := dec.DecodeInt32()
			if dec.Err() != nil {
				return nil, dec.Err()
			}

			if msgSetSize > 0 {
				// try to figure out what is next - MessageSet or RecordBatch

				b, err := br.Peek(17)
				if err != nil {
					return nil, err
				}
				part.MessageVersion = MessageVersion(int8(b[16]))

				if part.MessageVersion < MessageV2 {
					// Response contains MessageSet
					if part.Messages, err = readMessageSet(br, msgSetSize); err != nil {
						return nil, err
					}
					for _, msg := range part.Messages {
						msg.Topic = topic.Name
						msg.Partition = part.ID
						msg.TipOffset = part.TipOffset
					}
				} else if part.MessageVersion == MessageV2 {
					// Response contains RecordBatch
					if part.RecordBatch, err = readRecordBatch(br, msgSetSize); err != nil {
						return nil, err
					}
				} else {
					return nil, errors.New("Incorrect message byte")
				}
			}
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &resp, nil
}

const (
	CorrelationTypeGroup       int8 = 0
	CorrelationTypeTransaction      = 1
)

type ConsumerMetadataReq struct {
	RequestHeader
	ConsumerGroup   string
	CoordinatorType int8 // >= KafkaV1
}

func ReadConsumerMetadataReq(r io.Reader) (*ConsumerMetadataReq, error) {
	var req ConsumerMetadataReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	req.ConsumerGroup = dec.DecodeString()

	if req.version >= KafkaV1 {
		req.CoordinatorType = dec.DecodeInt8()
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r ConsumerMetadataReq) Kind() int16 {
	return ConsumerMetadataReqKind
}

func (r *ConsumerMetadataReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	enc.Encode(r.ConsumerGroup)

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *ConsumerMetadataReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type ConsumerMetadataResp struct {
	Version         int16
	CorrelationID   int32
	ThrottleTime    time.Duration // >= KafkaV1
	Err             error
	ErrMsg          string // >= KafkaV1
	CoordinatorID   int32
	CoordinatorHost string
	CoordinatorPort int32
}

func ReadConsumerMetadataResp(r io.Reader) (*ConsumerMetadataResp, error) {
	return ReadVersionedConsumerMetadataResp(r, KafkaV0)
}

func ReadVersionedConsumerMetadataResp(r io.Reader, version int16) (*ConsumerMetadataResp, error) {
	var resp ConsumerMetadataResp
	resp.Version = version
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	if version >= KafkaV1 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	resp.Err = errFromNo(dec.DecodeInt16())
	if version >= KafkaV1 {
		resp.ErrMsg = dec.DecodeString()
	}
	resp.CoordinatorID = dec.DecodeInt32()
	resp.CoordinatorHost = dec.DecodeString()
	resp.CoordinatorPort = dec.DecodeInt32()

	if err := dec.Err(); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *ConsumerMetadataResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV1 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeError(r.Err)

	if r.Version >= KafkaV1 {
		enc.Encode(r.ErrMsg)
	}

	enc.Encode(r.CoordinatorID)
	enc.Encode(r.CoordinatorHost)
	enc.Encode(r.CoordinatorPort)

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

type OffsetCommitReq struct {
	RequestHeader
	ConsumerGroup     string
	GroupGenerationID int32  // >= KafkaV1 only
	MemberID          string // >= KafkaV1 only
	RetentionTime     int64  // >= KafkaV2 only
	Topics            []OffsetCommitReqTopic
}

type OffsetCommitReqTopic struct {
	Name       string
	Partitions []OffsetCommitReqPartition
}

type OffsetCommitReqPartition struct {
	ID        int32
	Offset    int64
	TimeStamp time.Time // == KafkaV1 only
	Metadata  string
}

func ReadOffsetCommitReq(r io.Reader) (*OffsetCommitReq, error) {
	var req OffsetCommitReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	req.ConsumerGroup = dec.DecodeString()

	if req.version >= KafkaV1 {
		req.GroupGenerationID = dec.DecodeInt32()
		req.MemberID = dec.DecodeString()
	}

	if req.version >= KafkaV2 {
		req.RetentionTime = dec.DecodeInt64()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.Topics = make([]OffsetCommitReqTopic, len)

	for ti := range req.Topics {
		var topic = &req.Topics[ti]
		topic.Name = dec.DecodeString()

		len, err := dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		topic.Partitions = make([]OffsetCommitReqPartition, len)

		for pi := range topic.Partitions {
			var part = &topic.Partitions[pi]
			part.ID = dec.DecodeInt32()
			part.Offset = dec.DecodeInt64()

			if req.version == KafkaV1 {
				part.TimeStamp = time.Unix(0, dec.DecodeInt64()*int64(time.Millisecond))
			}

			part.Metadata = dec.DecodeString()
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r OffsetCommitReq) Kind() int16 {
	return OffsetCommitReqKind
}

func (r *OffsetCommitReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	enc.Encode(r.ConsumerGroup)

	if r.version >= KafkaV1 {
		enc.Encode(r.GroupGenerationID)
		enc.Encode(r.MemberID)
	}

	if r.version >= KafkaV2 {
		enc.Encode(r.RetentionTime)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.Encode(part.Offset)

			if r.version == KafkaV1 {
				// TODO(husio) is this really in milliseconds?
				enc.Encode(part.TimeStamp.UnixNano() / int64(time.Millisecond))
			}

			enc.Encode(part.Metadata)
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *OffsetCommitReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type OffsetCommitResp struct {
	Version       int16
	CorrelationID int32
	ThrottleTime  time.Duration // >= KafkaV3 only
	Topics        []OffsetCommitRespTopic
}

type OffsetCommitRespTopic struct {
	Name       string
	Partitions []OffsetCommitRespPartition
}

type OffsetCommitRespPartition struct {
	ID  int32
	Err error
}

func ReadOffsetCommitResp(r io.Reader) (*OffsetCommitResp, error) {
	return ReadVersionedOffsetCommitResp(r, KafkaV0)
}

func ReadVersionedOffsetCommitResp(r io.Reader, version int16) (*OffsetCommitResp, error) {
	var resp OffsetCommitResp
	resp.Version = version
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	if version >= KafkaV3 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Topics = make([]OffsetCommitRespTopic, len)

	for ti := range resp.Topics {
		var t = &resp.Topics[ti]
		t.Name = dec.DecodeString()

		len, err := dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		t.Partitions = make([]OffsetCommitRespPartition, len)

		for pi := range t.Partitions {
			var p = &t.Partitions[pi]
			p.ID = dec.DecodeInt32()
			p.Err = errFromNo(dec.DecodeInt16())
		}
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *OffsetCommitResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV3 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, t := range r.Topics {
		enc.Encode(t.Name)
		enc.EncodeArrayLen(len(t.Partitions))
		for _, p := range t.Partitions {
			enc.Encode(p.ID)
			enc.EncodeError(p.Err)
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil

}

type OffsetFetchReq struct {
	RequestHeader
	ConsumerGroup string
	Topics        []OffsetFetchReqTopic
}

type OffsetFetchReqTopic struct {
	Name       string
	Partitions []int32
}

func ReadOffsetFetchReq(r io.Reader) (*OffsetFetchReq, error) {
	var req OffsetFetchReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	req.ConsumerGroup = dec.DecodeString()

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.Topics = make([]OffsetFetchReqTopic, len)

	for ti := range req.Topics {
		var topic = &req.Topics[ti]
		topic.Name = dec.DecodeString()
		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		topic.Partitions = make([]int32, len)

		for pi := range topic.Partitions {
			topic.Partitions[pi] = dec.DecodeInt32()
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r OffsetFetchReq) Kind() int16 {
	return OffsetFetchReqKind
}

func (r *OffsetFetchReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	enc.Encode(r.ConsumerGroup)
	enc.EncodeArrayLen(len(r.Topics))
	for _, t := range r.Topics {
		enc.Encode(t.Name)
		enc.EncodeArrayLen(len(t.Partitions))
		for _, p := range t.Partitions {
			enc.Encode(p)
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *OffsetFetchReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type OffsetFetchResp struct {
	Version       int16
	CorrelationID int32
	ThrottleTime  time.Duration // >= KafkaV3
	Topics        []OffsetFetchRespTopic
	Err           error // >= KafkaV2
}

type OffsetFetchRespTopic struct {
	Name       string
	Partitions []OffsetFetchRespPartition
}

type OffsetFetchRespPartition struct {
	ID       int32
	Offset   int64
	Metadata string
	Err      error
}

func ReadOffsetFetchResp(r io.Reader) (*OffsetFetchResp, error) {
	return ReadVersionedOffsetFetchResp(r, KafkaV0)
}

func ReadVersionedOffsetFetchResp(r io.Reader, version int16) (*OffsetFetchResp, error) {
	var resp OffsetFetchResp
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	resp.Version = version

	if version >= KafkaV3 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Topics = make([]OffsetFetchRespTopic, len)

	for ti := range resp.Topics {
		var t = &resp.Topics[ti]
		t.Name = dec.DecodeString()

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		t.Partitions = make([]OffsetFetchRespPartition, len)

		for pi := range t.Partitions {
			var p = &t.Partitions[pi]
			p.ID = dec.DecodeInt32()
			p.Offset = dec.DecodeInt64()
			p.Metadata = dec.DecodeString()
			p.Err = errFromNo(dec.DecodeInt16())
		}
	}

	if version >= KafkaV2 {
		resp.Err = errFromNo(dec.DecodeInt16())
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *OffsetFetchResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV3 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.Encode(part.Offset)
			enc.Encode(part.Metadata)
			enc.EncodeError(part.Err)
		}
	}

	if r.Version >= KafkaV2 {
		enc.EncodeError(r.Err)
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

type ProduceReq struct {
	RequestHeader
	Compression     Compression // only used when sending ProduceReqs
	TransactionalID string
	RequiredAcks    int16
	Timeout         time.Duration
	Topics          []ProduceReqTopic
}

type ProduceReqTopic struct {
	Name       string
	Partitions []ProduceReqPartition
}

type ProduceReqPartition struct {
	ID       int32
	Messages []*Message
}

func ReadProduceReq(r io.Reader) (*ProduceReq, error) {
	var req ProduceReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	if req.version >= KafkaV3 {
		req.TransactionalID = dec.DecodeString()
	}

	req.RequiredAcks = dec.DecodeInt16()
	req.Timeout = time.Duration(dec.DecodeInt32()) * time.Millisecond

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.Topics = make([]ProduceReqTopic, len)

	for ti := range req.Topics {
		var topic = &req.Topics[ti]
		topic.Name = dec.DecodeString()

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		topic.Partitions = make([]ProduceReqPartition, len)

		for pi := range topic.Partitions {
			var part = &topic.Partitions[pi]
			part.ID = dec.DecodeInt32()
			if dec.Err() != nil {
				return nil, dec.Err()
			}
			msgSetSize := dec.DecodeInt32()
			if dec.Err() != nil {
				return nil, dec.Err()
			}
			var err error
			if part.Messages, err = readMessageSet(r, msgSetSize); err != nil {
				return nil, err
			}
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r ProduceReq) Kind() int16 {
	return ProduceReqKind
}

func (r *ProduceReq) Bytes() ([]byte, error) {
	var buf buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	if r.version >= KafkaV3 {
		enc.EncodeString(r.TransactionalID)
	}

	enc.EncodeInt16(r.RequiredAcks)
	enc.EncodeInt32(int32(r.Timeout / time.Millisecond))
	enc.EncodeArrayLen(len(r.Topics))
	for _, t := range r.Topics {
		enc.EncodeString(t.Name)
		enc.EncodeArrayLen(len(t.Partitions))
		for _, p := range t.Partitions {
			enc.EncodeInt32(p.ID)
			i := len(buf)
			enc.EncodeInt32(0) // placeholder
			n, err := writeMessageSet(&buf, p.Messages, r.Compression)
			if err != nil {
				return nil, err
			}
			binary.BigEndian.PutUint32(buf[i:i+4], uint32(n))
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(buf)-4))
	return []byte(buf), nil
}

func (r *ProduceReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type ProduceResp struct {
	Version       int16
	CorrelationID int32
	Topics        []ProduceRespTopic
	ThrottleTime  time.Duration
}

type ProduceRespTopic struct {
	Name       string
	Partitions []ProduceRespPartition
}

type ProduceRespPartition struct {
	ID            int32
	Err           error
	Offset        int64
	LogAppendTime int64
}

func (r *ProduceResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)
	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.EncodeError(part.Err)
			enc.Encode(part.Offset)

			if r.Version >= KafkaV2 {
				enc.Encode(part.LogAppendTime)
			}
		}
	}

	if r.Version >= KafkaV1 {
		enc.Encode(r.ThrottleTime)
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func ReadProduceResp(r io.Reader) (*ProduceResp, error) {
	return ReadVersionedProduceResp(r, KafkaV0)
}

func ReadVersionedProduceResp(r io.Reader, version int16) (*ProduceResp, error) {
	var resp ProduceResp
	dec := NewDecoder(r)
	resp.Version = version

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()
	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Topics = make([]ProduceRespTopic, len)

	for ti := range resp.Topics {
		var t = &resp.Topics[ti]
		t.Name = dec.DecodeString()

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		t.Partitions = make([]ProduceRespPartition, len)

		for pi := range t.Partitions {
			var p = &t.Partitions[pi]
			p.ID = dec.DecodeInt32()
			p.Err = errFromNo(dec.DecodeInt16())
			p.Offset = dec.DecodeInt64()
			if resp.Version >= KafkaV2 {
				p.LogAppendTime = dec.DecodeInt64()
			}
		}
	}

	if resp.Version >= KafkaV1 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}
	return &resp, nil
}

type OffsetReq struct {
	RequestHeader
	ReplicaID      int32
	IsolationLevel int8
	Topics         []OffsetReqTopic
}

type OffsetReqTopic struct {
	Name       string
	Partitions []OffsetReqPartition
}

type OffsetReqPartition struct {
	ID         int32
	TimeMs     int64 // cannot be time.Time because of negative values
	MaxOffsets int32 // == KafkaV0 only
}

func ReadOffsetReq(r io.Reader) (*OffsetReq, error) {
	var req OffsetReq
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	// api key
	_ = dec.DecodeInt16()
	req.version = dec.DecodeInt16()
	req.correlationID = dec.DecodeInt32()
	req.ClientID = dec.DecodeString()
	req.ReplicaID = dec.DecodeInt32()

	if req.version >= KafkaV2 {
		req.IsolationLevel = dec.DecodeInt8()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.Topics = make([]OffsetReqTopic, len)

	for ti := range req.Topics {
		var topic = &req.Topics[ti]
		topic.Name = dec.DecodeString()

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		topic.Partitions = make([]OffsetReqPartition, len)

		for pi := range topic.Partitions {
			var part = &topic.Partitions[pi]
			part.ID = dec.DecodeInt32()
			part.TimeMs = dec.DecodeInt64()

			if req.version == KafkaV0 {
				part.MaxOffsets = dec.DecodeInt32()
			}
		}
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r OffsetReq) Kind() int16 {
	return OffsetReqKind
}

func (r *OffsetReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	//enc.Encode(r.ReplicaID)
	enc.Encode(int32(-1))

	if r.version >= KafkaV2 {
		enc.Encode(r.IsolationLevel)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.Encode(part.TimeMs)

			if r.version == KafkaV0 {
				enc.Encode(part.MaxOffsets)
			}
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *OffsetReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type OffsetResp struct {
	Version       int16
	CorrelationID int32
	ThrottleTime  time.Duration
	Topics        []OffsetRespTopic
}

type OffsetRespTopic struct {
	Name       string
	Partitions []OffsetRespPartition
}

type OffsetRespPartition struct {
	ID        int32
	Err       error
	TimeStamp time.Time // >= KafkaV1 only
	Offsets   []int64   // used in KafkaV0
}

func ReadOffsetResp(r io.Reader) (*OffsetResp, error) {
	return ReadVersionedOffsetResp(r, KafkaV0)
}

func ReadVersionedOffsetResp(r io.Reader, version int16) (*OffsetResp, error) {
	var resp OffsetResp
	dec := NewDecoder(r)
	resp.Version = version

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	if version >= KafkaV2 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.Topics = make([]OffsetRespTopic, len)

	for ti := range resp.Topics {
		var t = &resp.Topics[ti]
		t.Name = dec.DecodeString()

		len, err = dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		t.Partitions = make([]OffsetRespPartition, len)

		for pi := range t.Partitions {
			var p = &t.Partitions[pi]
			p.ID = dec.DecodeInt32()
			p.Err = errFromNo(dec.DecodeInt16())

			if version >= KafkaV1 {
				p.TimeStamp = time.Unix(0, dec.DecodeInt64()*int64(time.Millisecond))

				// in kafka >= KafkaV1 offset can be only one number.
				// But for compatibility we still use slice
				offset := dec.DecodeInt64()
				p.Offsets = []int64{offset}
			} else {
				len, err = dec.DecodeArrayLen()
				if err != nil {
					return nil, err
				}
				p.Offsets = make([]int64, len)

				for oi := range p.Offsets {
					p.Offsets[oi] = dec.DecodeInt64()
				}
			}
		}
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *OffsetResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV2 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeArrayLen(len(r.Topics))
	for _, topic := range r.Topics {
		enc.Encode(topic.Name)
		enc.EncodeArrayLen(len(topic.Partitions))
		for _, part := range topic.Partitions {
			enc.Encode(part.ID)
			enc.EncodeError(part.Err)

			if r.Version >= KafkaV1 {
				enc.Encode(part.TimeStamp.UnixNano() / int64(time.Millisecond))

				// in kafka >= KafkaV1 offset can be only one value.
				// In this case we use first element of slice
				var offset int64
				if len(part.Offsets) > 0 {
					offset = part.Offsets[0]
				}
				enc.Encode(offset)
			} else {
				enc.EncodeArrayLen(len(part.Offsets))
				for _, off := range part.Offsets {
					enc.Encode(off)
				}
			}
		}
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

type ReplicaAssignment struct {
	Partition int32
	Replicas  []int32
}
type ConfigEntry struct {
	ConfigName  string
	ConfigValue string
}

type TopicInfo struct {
	Topic              string
	NumPartitions      int32
	ReplicationFactor  int16
	ReplicaAssignments []ReplicaAssignment
	ConfigEntries      []ConfigEntry
}

type CreateTopicsReq struct {
	RequestHeader
	CreateTopicsRequests []TopicInfo
	Timeout              time.Duration
	ValidateOnly         bool
}

func ReadCreateTopicsReq(r io.Reader) (*CreateTopicsReq, error) {
	var req CreateTopicsReq
	dec := NewDecoder(r)

	decodeHeader(dec, &req)

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	req.CreateTopicsRequests = make([]TopicInfo, len)

	for i := range req.CreateTopicsRequests {
		ti := TopicInfo{}
		ti.Topic = dec.DecodeString()
		ti.NumPartitions = dec.DecodeInt32()
		ti.ReplicationFactor = dec.DecodeInt16()
		len, err := dec.DecodeArrayLen()
		if err != nil {
			return nil, err
		}

		ti.ReplicaAssignments = make([]ReplicaAssignment, len)
		for j := range ti.ReplicaAssignments {
			ra := ReplicaAssignment{}
			ra.Partition = dec.DecodeInt32()
			len, err = dec.DecodeArrayLen()
			ra.Replicas = make([]int32, len)
			for k := range ra.Replicas {
				ra.Replicas[k] = dec.DecodeInt32()
			}

			ti.ReplicaAssignments[j] = ra
		}
		len, err = dec.DecodeArrayLen()
		ti.ConfigEntries = make([]ConfigEntry, len)
		for l := range ti.ConfigEntries {
			ce := ConfigEntry{}
			ce.ConfigName = dec.DecodeString()
			ce.ConfigValue = dec.DecodeString()
			ti.ConfigEntries[l] = ce
		}

		req.CreateTopicsRequests[i] = ti
	}

	req.Timeout = dec.DecodeDuration32()

	if req.version >= KafkaV1 {
		req.ValidateOnly = dec.DecodeInt8() != 0
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r CreateTopicsReq) Kind() int16 {
	return CreateTopicsReqKind
}

func (r *CreateTopicsReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	enc.EncodeArrayLen(len(r.CreateTopicsRequests))
	for _, topicInfo := range r.CreateTopicsRequests {
		enc.Encode(topicInfo.Topic)
		enc.Encode(topicInfo.NumPartitions)
		enc.Encode(topicInfo.ReplicationFactor)
		enc.EncodeArrayLen(len(topicInfo.ReplicaAssignments))
		for _, replicaAssignment := range topicInfo.ReplicaAssignments {
			enc.Encode(replicaAssignment.Partition)
			enc.EncodeArrayLen(len(replicaAssignment.Replicas))
			for _, replica := range replicaAssignment.Replicas {
				enc.Encode(replica)
			}

		}

		enc.EncodeArrayLen(len(topicInfo.ConfigEntries))
		for _, ce := range topicInfo.ConfigEntries {
			enc.Encode(ce.ConfigName)
			enc.Encode(ce.ConfigValue)
		}
	}

	enc.Encode(r.Timeout)

	if r.version >= KafkaV1 {
		enc.Encode(boolToInt8(r.ValidateOnly))
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *CreateTopicsReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type TopicError struct {
	Topic        string
	ErrorCode    int16
	ErrorMessage string // >= KafkaV1
	Err          error
}

type CreateTopicsResp struct {
	Version       int16
	CorrelationID int32
	TopicErrors   []TopicError
	ThrottleTime  time.Duration // >= KafkaV2
}

func (r *CreateTopicsResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)

	if r.Version >= KafkaV2 {
		enc.Encode(r.ThrottleTime)
	}

	enc.EncodeArrayLen(len(r.TopicErrors))
	for _, te := range r.TopicErrors {
		enc.Encode(te.Topic)
		enc.Encode(te.ErrorCode)
		if r.Version >= KafkaV1 {
			enc.Encode(te.ErrorMessage)
		}

	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func ReadCreateTopicsResp(r io.Reader) (*CreateTopicsResp, error) {
	return ReadVersionedCreateTopicsResp(r, KafkaV0)
}

func ReadVersionedCreateTopicsResp(r io.Reader, version int16) (*CreateTopicsResp, error) {
	var resp CreateTopicsResp
	resp.Version = version
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()

	if resp.Version >= KafkaV2 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}
	resp.TopicErrors = make([]TopicError, len)

	for i := range resp.TopicErrors {
		var te = &resp.TopicErrors[i]
		te.Topic = dec.DecodeString()
		te.ErrorCode = dec.DecodeInt16()
		if resp.Version >= KafkaV1 {
			te.ErrorMessage = dec.DecodeString()
		}
		te.Err = errFromNo(te.ErrorCode)
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &resp, nil
}

type buffer []byte

func (b *buffer) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}

type APIVersionsReq struct {
	RequestHeader
}

func ReadAPIVersionsReq(r io.Reader) (*APIVersionsReq, error) {
	var req APIVersionsReq
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	// api key + api version
	_ = dec.DecodeInt32()
	req.correlationID = dec.DecodeInt32()
	req.ClientID = dec.DecodeString()

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &req, nil
}

func (r APIVersionsReq) Kind() int16 {
	return APIVersionsReqKind
}

func (r *APIVersionsReq) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	encodeHeader(enc, r)

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func (r *APIVersionsReq) WriteTo(w io.Writer) (int64, error) {
	b, err := r.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

type APIVersionsResp struct {
	Version       int16
	CorrelationID int32
	APIVersions   []SupportedVersion
	ThrottleTime  time.Duration
}

type SupportedVersion struct {
	APIKey     int16
	MinVersion int16
	MaxVersion int16
}

func (r *APIVersionsResp) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// message size - for now just placeholder
	enc.Encode(int32(0))
	enc.Encode(r.CorrelationID)
	//error code
	enc.Encode(int16(0))
	enc.EncodeArrayLen(len(r.APIVersions))
	for _, api := range r.APIVersions {
		enc.Encode(api.APIKey)
		enc.Encode(api.MinVersion)
		enc.Encode(api.MaxVersion)
	}

	if r.Version >= KafkaV1 {
		enc.Encode(r.ThrottleTime)
	}

	if enc.Err() != nil {
		return nil, enc.Err()
	}

	// update the message size information
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))

	return b, nil
}

func ReadAPIVersionsResp(r io.Reader) (*APIVersionsResp, error) {
	return ReadVersionedAPIVersionsResp(r, KafkaV0)
}

func ReadVersionedAPIVersionsResp(r io.Reader, version int16) (*APIVersionsResp, error) {
	var resp APIVersionsResp
	resp.Version = version
	dec := NewDecoder(r)

	// total message size
	_ = dec.DecodeInt32()
	resp.CorrelationID = dec.DecodeInt32()
	errcode := dec.DecodeInt16()
	if errcode != 0 {
		//TODO fill app error
		return nil, fmt.Errorf("versioning error: %d", errcode)
	}
	len, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, err
	}

	resp.APIVersions = make([]SupportedVersion, len)
	for i := range resp.APIVersions {
		api := &resp.APIVersions[i]
		api.APIKey = dec.DecodeInt16()
		api.MinVersion = dec.DecodeInt16()
		api.MaxVersion = dec.DecodeInt16()
	}

	if version >= KafkaV1 {
		resp.ThrottleTime = dec.DecodeDuration32()
	}

	if dec.Err() != nil {
		return nil, dec.Err()
	}
	return &resp, nil
}
