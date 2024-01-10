// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	. "github.com/cilium/checkmate"
)

type EncryptStatusSuite struct{}

var _ = Suite(&EncryptStatusSuite{})

const procTestFixtures = "fixtures/proc"

func (s *EncryptStatusSuite) TestGetXfrmStats(c *C) {
	errCount, m, err := getXfrmStats(procTestFixtures)
	c.Assert(err, Equals, nil)
	currentCount := int64(0)
	testCases := []struct {
		name string
		want int64
	}{
		{name: "XfrmInError", want: 2},
		{name: "XfrmInBufferError", want: 0},
		{name: "XfrmInHdrError", want: 0},
		{name: "XfrmInNoStates", want: 225479},
		{name: "XfrmInStateProtoError", want: 141222},
		{name: "XfrmInStateModeError", want: 0},
		{name: "XfrmInStateSeqError", want: 0},
		{name: "XfrmInStateExpired", want: 0},
		{name: "XfrmInStateMismatch", want: 0},
		{name: "XfrmInStateInvalid", want: 0},
		{name: "XfrmInTmplMismatch", want: 0},
		{name: "XfrmInNoPols", want: 203389},
		{name: "XfrmInPolBlock", want: 0},
		{name: "XfrmInPolError", want: 0},
		{name: "XfrmOutError", want: 0},
		{name: "XfrmOutBundleGenError", want: 0},
		{name: "XfrmOutBundleCheckError", want: 0},
		{name: "XfrmOutNoStates", want: 36162},
		{name: "XfrmOutStateProtoError", want: 1886},
		{name: "XfrmOutStateModeError", want: 0},
		{name: "XfrmOutStateSeqError", want: 0},
		{name: "XfrmOutStateExpired", want: 0},
		{name: "XfrmOutPolBlock", want: 0},
		{name: "XfrmOutPolDead", want: 0},
		{name: "XfrmOutPolError", want: 0},
		{name: "XfrmFwdHdrError", want: 0},
		{name: "XfrmOutStateInvalid", want: 0},
		{name: "XfrmAcquireError", want: 0},
	}
	for _, test := range testCases {
		got := m[test.name]
		c.Assert(test.want, Equals, got)
		currentCount += got
	}
	c.Assert(currentCount, Equals, errCount)
}

func (s *EncryptStatusSuite) TestExtractMaxSequenceNumber(c *C) {
	ipOutput := `src 10.84.1.32 dst 10.84.0.30
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0x3cb23e00/0xffffff00 output-mark 0xe00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0xc3, bitmap 0x00000000
	sel src 0.0.0.0/0 dst 0.0.0.0/0
src 0.0.0.0 dst 10.84.1.32
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0xd00/0xf00 output-mark 0xd00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0x1410, bitmap 0x00000000
	sel src 0.0.0.0/0 dst 0.0.0.0/0
src 10.84.1.32 dst 10.84.2.145
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0x7e63e00/0xffffff00 output-mark 0xe00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0x13e0, bitmap 0x00000000
	sel src 0.0.0.0/0 dst 0.0.0.0/0`

	maxSeqNumber, err := extractMaxSequenceNumber(ipOutput)
	c.Assert(err, Equals, nil)
	c.Assert(maxSeqNumber, Equals, int64(0x1410))
}

// Attempt to simulate a case where the output would be interrupted mid-sentence.
func (s *EncryptStatusSuite) TestExtractMaxSequenceNumberError(c *C) {
	ipOutput := `src 10.84.1.32 dst 10.84.0.30
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0x3cb23e00/0xffffff00 output-mark 0xe00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0x`

	maxSeqNumber, err := extractMaxSequenceNumber(ipOutput)
	c.Assert(err, Equals, nil)
	c.Assert(maxSeqNumber, Equals, int64(0))
}
