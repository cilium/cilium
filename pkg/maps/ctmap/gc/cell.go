// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"errors"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/signal"
)

// Cell registers a signal handler for CT and NAT fill-up signals.
var Cell = cell.Invoke(registerSignalHandler)

// SignalData holds the IP address family type BPF program sent along with
// the SignalNatFillUp and SignalCTFillUp signals.
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

// Ugly global variables to bridge the old with the new

// wakeup is buffered to not block the sender while GC is running. If this overflows it is possible
// to lose a wakeup signal for IPv4 while IPv6 GC is running, and all the buffered wakeups are for
// IPv6 and the ones for IPv4 overflowed. Keep the buffer big enough for that to be unlikely.
var wakeup = make(chan SignalData, 1024)
var muteSignals = func() error { return errors.New("muteSignals not implemented") }
var unmuteSignals = func() error { return errors.New("unmuteSignals not implemented") }

func registerSignalHandler(sm signal.SignalManager) {
	err := sm.RegisterHandler(signal.ChannelHandler(wakeup), signal.SignalCTFillUp, signal.SignalNatFillUp)
	if err != nil {
		log.WithError(err).Warningf("Failed to set up signal channel for CT & NAT fill-up events!")
		return
	}
	muteSignals = func() error {
		return sm.MuteSignals(signal.SignalCTFillUp, signal.SignalNatFillUp)
	}
	unmuteSignals = func() error {
		return sm.UnmuteSignals(signal.SignalCTFillUp, signal.SignalNatFillUp)
	}
}
