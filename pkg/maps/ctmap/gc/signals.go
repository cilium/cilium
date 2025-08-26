// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"fmt"

	"github.com/cilium/cilium/pkg/signal"
)

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

type SignalHandler struct {
	signals chan SignalData
	manager signal.SignalManager
}

func newSignalHandler(sm signal.SignalManager) (SignalHandler, error) {
	handler := SignalHandler{
		// wakeup is buffered to not block the sender while GC is running. If this overflows it is possible
		// to lose a wakeup signal for IPv4 while IPv6 GC is running, and all the buffered wakeups are for
		// IPv6 and the ones for IPv4 overflowed. Keep the buffer big enough for that to be unlikely.
		signals: make(chan SignalData, 1024),
		manager: sm,
	}

	err := sm.RegisterHandler(signal.ChannelHandler(handler.signals), signal.SignalCTFillUp, signal.SignalNatFillUp)
	if err != nil {
		return SignalHandler{}, fmt.Errorf("failed to set up signal channel for CT & NAT fill-up events: %w", err)
	}

	return handler, nil
}

func (sh *SignalHandler) Signals() <-chan SignalData {
	return sh.signals
}

func (sh *SignalHandler) MuteSignals() error {
	return sh.manager.MuteSignals(signal.SignalCTFillUp, signal.SignalNatFillUp)
}

func (sh *SignalHandler) UnmuteSignals() error {
	return sh.manager.UnmuteSignals(signal.SignalCTFillUp, signal.SignalNatFillUp)
}
