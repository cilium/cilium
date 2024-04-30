// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signal

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
)

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

func TestSignalSet(t *testing.T) {
	buf := new(bytes.Buffer)
	binary.Write(buf, byteorder.Native, SignalNatFillUp)

	events := &testReader{cpu: 1, data: buf.Bytes()}
	sm := &signalManager{events: events}
	require.Equal(t, true, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	// invalid signal, nothing changes
	err := sm.UnmuteSignals(SignalType(16))
	require.Error(t, err)
	require.ErrorContains(t, err, "signal number not supported: 16")
	require.Equal(t, true, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	// 2 active signals
	err = sm.UnmuteSignals(SignalNatFillUp, SignalCTFillUp)
	require.Nil(t, err)
	require.Equal(t, false, sm.isMuted())
	require.Equal(t, false, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, false, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	require.Equal(t, false, events.paused)
	require.Equal(t, false, events.closed)

	// Mute one, one still active
	err = sm.MuteSignals(SignalNatFillUp)
	require.Nil(t, err)
	require.Equal(t, false, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, false, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	require.Equal(t, false, events.paused)
	require.Equal(t, false, events.closed)

	// Nothing happens if the signal is already muted
	err = sm.MuteSignals(SignalNatFillUp)
	require.Nil(t, err)
	require.Equal(t, false, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, false, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	require.Equal(t, false, events.paused)
	require.Equal(t, false, events.closed)

	// Unmute one more
	err = sm.UnmuteSignals(SignalAuthRequired)
	require.Nil(t, err)
	require.Equal(t, false, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, false, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, false, sm.isSignalMuted(SignalAuthRequired))

	require.Equal(t, false, events.paused)
	require.Equal(t, false, events.closed)

	// Last signala are muted
	err = sm.MuteSignals(SignalCTFillUp, SignalAuthRequired)
	require.Nil(t, err)
	require.Equal(t, true, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	require.Equal(t, true, events.paused)
	require.Equal(t, false, events.closed)

	// A signal is unmuted again
	err = sm.UnmuteSignals(SignalCTFillUp)
	require.Nil(t, err)
	require.Equal(t, false, sm.isMuted())
	require.Equal(t, true, sm.isSignalMuted(SignalNatFillUp))
	require.Equal(t, false, sm.isSignalMuted(SignalCTFillUp))
	require.Equal(t, true, sm.isSignalMuted(SignalAuthRequired))

	require.Equal(t, false, events.paused)
	require.Equal(t, false, events.closed)
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

func TestLifeCycle(t *testing.T) {
	logging.SetLogLevelToDebug()

	buf1 := new(bytes.Buffer)
	binary.Write(buf1, byteorder.Native, SignalNatFillUp)
	binary.Write(buf1, byteorder.Native, SignalProtoV4)

	buf2 := new(bytes.Buffer)
	binary.Write(buf2, byteorder.Native, SignalCTFillUp)
	binary.Write(buf2, byteorder.Native, SignalProtoV4)

	messages := [][]byte{buf1.Bytes(), buf2.Bytes()}

	sm := newSignalManager(fakesignalmap.NewFakeSignalMap(messages, time.Second))
	require.Equal(t, true, sm.isMuted())

	wakeup := make(chan SignalData, 1024)
	err := sm.RegisterHandler(ChannelHandler(wakeup), SignalNatFillUp, SignalCTFillUp)
	require.Nil(t, err)
	require.Equal(t, false, sm.isMuted())

	err = sm.start()
	require.Nil(t, err)

	select {
	case x := <-wakeup:
		sm.MuteSignals(SignalNatFillUp, SignalCTFillUp)
		require.Equal(t, true, sm.isMuted())

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

		require.Equal(t, true, ipv4)
		require.Equal(t, false, ipv6)

	case <-time.After(5 * time.Second):
		sm.MuteSignals(SignalNatFillUp, SignalCTFillUp)
		require.Equal(t, true, sm.isMuted())

		t.Fatal("No signals received on time.")
	}

	err = sm.stop()
	require.Nil(t, err)
}
