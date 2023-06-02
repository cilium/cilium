// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signal

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/cilium/ebpf/perf"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
)

// Hook up gocheck into the "go test" runner.
type signalSuite struct{}

var _ = Suite(&signalSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

type testReader struct {
	paused bool
	closed bool
	cpu    int
	data   []byte
	lost   uint64
}

func (r *testReader) Read() (perf.Record, error) {
	if r.closed {
		return perf.Record{}, io.EOF
	}
	return perf.Record{CPU: r.cpu, RawSample: r.data, LostSamples: r.lost}, nil
}

func (r *testReader) Pause() error {
	r.paused = true
	return nil
}

func (r *testReader) Resume() error {
	r.paused = false
	return nil
}

func (r *testReader) Close() error {
	if r.closed {
		return io.EOF
	}
	r.closed = true
	return nil
}

func (t *signalSuite) TestSignalSet(c *C) {
	buf := new(bytes.Buffer)
	binary.Write(buf, byteorder.Native, SignalNatFillUp)

	events := &testReader{cpu: 1, data: buf.Bytes()}
	sm := &signalManager{events: events}
	c.Assert(sm.isMuted(), Equals, true)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	// invalid signal, nothing changes
	err := sm.UnmuteSignals(SignalType(16))
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "signal number not supported: 16")
	c.Assert(sm.isMuted(), Equals, true)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	// 2 active signals
	err = sm.UnmuteSignals(SignalNatFillUp, SignalCTFillUp)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, false)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, false)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, false)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	c.Assert(events.paused, Equals, false)
	c.Assert(events.closed, Equals, false)

	// Mute one, one still active
	err = sm.MuteSignals(SignalNatFillUp)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, false)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, false)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	c.Assert(events.paused, Equals, false)
	c.Assert(events.closed, Equals, false)

	// Nothing happens if the signal is already muted
	err = sm.MuteSignals(SignalNatFillUp)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, false)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, false)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	c.Assert(events.paused, Equals, false)
	c.Assert(events.closed, Equals, false)

	// Unmute one more
	err = sm.UnmuteSignals(SignalAuthRequired)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, false)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, false)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, false)

	c.Assert(events.paused, Equals, false)
	c.Assert(events.closed, Equals, false)

	// Last signala are muted
	err = sm.MuteSignals(SignalCTFillUp, SignalAuthRequired)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, true)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	c.Assert(events.paused, Equals, true)
	c.Assert(events.closed, Equals, false)

	// A signal is unmuted again
	err = sm.UnmuteSignals(SignalCTFillUp)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, false)
	c.Assert(sm.isSignalMuted(SignalNatFillUp), Equals, true)
	c.Assert(sm.isSignalMuted(SignalCTFillUp), Equals, false)
	c.Assert(sm.isSignalMuted(SignalAuthRequired), Equals, true)

	c.Assert(events.paused, Equals, false)
	c.Assert(events.closed, Equals, false)
}

type SignalData uint32

const (
	// SignalProtoV4 denotes IPv4 protocol
	SignalProtoV4 SignalData = iota
	// SignalProtoV6 denotes IPv6 protocol
	SignalProtoV6
	SignalProtoMax
)

var signalProto = [SignalProtoMax]string{
	SignalProtoV4: "ipv4",
	SignalProtoV6: "ipv6",
}

// String implements fmt.Stringer for SignalData
func (d SignalData) String() string {
	return signalProto[d]
}

func (t *signalSuite) TestLifeCycle(c *C) {
	logging.SetLogLevelToDebug()

	buf1 := new(bytes.Buffer)
	binary.Write(buf1, byteorder.Native, SignalNatFillUp)
	binary.Write(buf1, byteorder.Native, SignalProtoV4)

	buf2 := new(bytes.Buffer)
	binary.Write(buf2, byteorder.Native, SignalCTFillUp)
	binary.Write(buf2, byteorder.Native, SignalProtoV4)

	messages := [][]byte{buf1.Bytes(), buf2.Bytes()}

	sm := newSignalManager(fakesignalmap.NewFakeSignalMap(messages, time.Second))
	c.Assert(sm.isMuted(), Equals, true)

	wakeup := make(chan SignalData, 1024)
	err := sm.RegisterHandler(ChannelHandler(wakeup), SignalNatFillUp, SignalCTFillUp)
	c.Assert(err, IsNil)
	c.Assert(sm.isMuted(), Equals, false)

	err = sm.start()
	c.Assert(err, IsNil)

	select {
	case x := <-wakeup:
		sm.MuteSignals(SignalNatFillUp, SignalCTFillUp)
		c.Assert(sm.isMuted(), Equals, true)

		ipv4 := false
		ipv6 := false
		if x == SignalProtoV4 {
			ipv4 = true
		} else if x == SignalProtoV6 {
			ipv6 = true
		}

		// Drain current queue since we just woke up anyway.
		for len(wakeup) > 0 {
			x := <-wakeup
			if x == SignalProtoV4 {
				ipv4 = true
			} else if x == SignalProtoV6 {
				ipv6 = true
			}
		}

		c.Assert(ipv4, Equals, true)
		c.Assert(ipv6, Equals, false)

	case <-time.After(5 * time.Second):
		sm.MuteSignals(SignalNatFillUp, SignalCTFillUp)
		c.Assert(sm.isMuted(), Equals, true)

		c.Fatal("No signals received on time.")
	}

	err = sm.stop()
	c.Assert(err, IsNil)
}
