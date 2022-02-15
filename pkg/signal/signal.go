// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"

	oldBPF "github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// SignalNatFillUp denotes potential congestion on the NAT table
	SignalNatFillUp = iota
	// SignalCTFillUp denotes potential congestion on the CT table
	SignalCTFillUp
	SignalTypeMax
)

const (
	// SignalProtoV4 denotes IPv4 protocol
	SignalProtoV4 = iota
	// SignalProtoV6 denotes IPv6 protocol
	SignalProtoV6
	SignalProtoMax
)

const (
	// SignalWakeGC triggers wake-up of the CT garbage collector
	SignalWakeGC = iota
	// SignalChanInvalid must be last one
	SignalChanInvalid
	SignalChanMax
)

// SignalData holds actual data the BPF program sent along with
// the signal. Can be extended upon need for new signals.
type SignalData uint32

// SignalMsg is the message we receive from BPF datapath
type SignalMsg struct {
	Which uint32
	Data  SignalData
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "signal")

	channels [SignalChanMax]chan<- SignalData

	once   sync.Once
	events *perf.Reader

	signalName = [SignalTypeMax]string{
		SignalNatFillUp: "nat_fill_up",
		SignalCTFillUp:  "ct_fill_up",
	}
	signalProto = [SignalProtoMax]string{
		SignalProtoV4: "ipv4",
		SignalProtoV6: "ipv6",
	}
)

func signalCollectMetrics(sig *SignalMsg, signalStatus string) {
	signalType := ""
	signalData := ""
	if sig != nil {
		signalType = signalName[sig.Which]
		if sig.Which == SignalNatFillUp ||
			sig.Which == SignalCTFillUp {
			signalData = signalProto[sig.Data]
		}
	}
	metrics.SignalsHandled.WithLabelValues(signalType, signalData, signalStatus).Inc()
}

func signalReceive(msg *perf.Record) {
	sig := SignalMsg{}
	if err := binary.Read(bytes.NewReader(msg.RawSample), byteorder.Native, &sig); err != nil {
		log.WithError(err).Warningf("Cannot parse signal from BPF datapath")
		return
	}
	sigChan := SignalChanInvalid
	switch sig.Which {
	case SignalNatFillUp, SignalCTFillUp:
		sigChan = SignalWakeGC
	}
	if channels[sigChan] != nil {
		channels[sigChan] <- sig.Data
		signalCollectMetrics(&sig, "received")
	}
}

// MuteChannel tells to not send any new events to a particular channel
// for a given signal.
func MuteChannel(signal int) error {
	if signal != SignalWakeGC {
		return fmt.Errorf("Signal number not supported: %d", signal)
	}
	// Right now we only support 1 type of signal, we may extend this in
	// future. If all signals are muted, then we can simply turn off perf
	// RB notifications from kernel side, which is much more efficient as
	// no new message is pushed into the RB.
	if events != nil {
		events.Pause()
	}
	return nil
}

// UnmuteChannel tells to allow sending new events to a particular channel
// for a given signal.
func UnmuteChannel(signal int) error {
	if signal != SignalWakeGC {
		return fmt.Errorf("Signal number not supported: %d", signal)
	}
	// See comment in MuteChannel().
	if events != nil {
		events.Resume()
	}
	return nil
}

// RegisterChannel registers a go channel for a given signal.
func RegisterChannel(signal int, ch chan<- SignalData) error {
	if signal >= SignalChanInvalid {
		return fmt.Errorf("Signal number not supported: %d", signal)
	}
	if channels[signal] != nil {
		return fmt.Errorf("Channel for signal number already registered: %d", signal)
	}

	channels[signal] = ch
	return nil
}

// SetupSignalListener bootstraps signal listener infrastructure.
func SetupSignalListener() {
	once.Do(func() {
		var err error

		path := oldBPF.MapPath(signalmap.MapName)
		signalMap, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			log.WithError(err).Warningf("Failed to open signals map")
			return
		}
		events, err = perf.NewReader(signalMap, os.Getpagesize())
		if err != nil {
			log.WithError(err).Warningf("Cannot open %s map! Ignoring signals!",
				signalmap.MapName)
			return
		}

		go func() {
			log.Info("Datapath signal listener running")
			for {
				record, err := events.Read()
				switch {
				case err != nil:
					signalCollectMetrics(nil, "error")
					log.WithError(err).WithFields(logrus.Fields{
						logfields.BPFMapName: signalmap.MapName,
					}).Errorf("failed to read event")
				case record.LostSamples > 0:
					signalCollectMetrics(nil, "lost")
				default:
					signalReceive(&record)
				}
			}
		}()
	})
}
