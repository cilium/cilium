// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package payload

import (
	"bytes"
	"encoding/gob"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

func Test(t *testing.T) { TestingT(t) }

type PayloadSuite struct{}

var _ = Suite(&PayloadSuite{})

func (s *PayloadSuite) TestMeta_UnMarshalBinary(c *C) {
	meta1 := Meta{Size: 1234}
	buf, err := meta1.MarshalBinary()
	c.Assert(err, Equals, nil)

	var meta2 Meta
	err = meta2.UnmarshalBinary(buf)
	c.Assert(err, Equals, nil)

	c.Assert(meta1, checker.DeepEquals, meta2)
}

func (s *PayloadSuite) TestPayload_UnMarshalBinary(c *C) {
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}
	buf, err := payload1.Encode()
	c.Assert(err, Equals, nil)

	var payload2 Payload
	err = payload2.Decode(buf)
	c.Assert(err, Equals, nil)

	c.Assert(payload1, checker.DeepEquals, payload2)
}

func (s *PayloadSuite) BenchmarkWritePayloadReuseEncoder(c *C) {
	payload := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	// Do a first dry run to pre-allocate the buffer capacity.
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := payload.EncodeBinary(enc)
	c.Assert(err, Equals, nil)

	for i := 0; i < c.N; i++ {
		buf.Reset()
		err := payload.EncodeBinary(enc)
		c.Assert(err, Equals, nil)
	}
}

func (s *PayloadSuite) BenchmarkReadPayloadRuseEncoder(c *C) {
	payload := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	var buf bytes.Buffer

	// prefill an encoded stream
	enc := gob.NewEncoder(&buf)
	for i := 0; i < c.N; i++ {
		err := payload.EncodeBinary(enc)
		c.Assert(err, Equals, nil)
	}

	dec := gob.NewDecoder(&buf)
	for i := 0; i < c.N; i++ {
		err := payload.DecodeBinary(dec)
		c.Assert(err, Equals, nil)
	}
}
