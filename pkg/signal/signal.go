// Copyright 2019-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	oldBPF "github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

const (
	// SignalNatFillUp denotes potential congestion on the NAT table
	SignalNatFillUp = iota
	SignalTypeMax
)

const (
	// SignalNatV4 denotes NAT IPv4 table
	SignalNatV4 = iota
	// SignalNatV6 denotes NAT IPv6 table
	SignalNatV6
	SignalNatMax
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

	channels [SignalTypeMax]chan<- SignalData

	once   sync.Once
	events *perf.Reader

	signalName = [SignalTypeMax]string{
		SignalNatFillUp: "nat_fill_up",
	}
	signalNatProto = [SignalNatMax]string{
		SignalNatV4: "ipv4",
		SignalNatV6: "ipv6",
	}
)

func signalCollectMetrics(sig *SignalMsg, signalStatus string) {
	signalType := ""
	signalData := ""
	if sig != nil {
		signalType = signalName[sig.Which]
		if sig.Which == SignalNatFillUp {
			signalData = signalNatProto[sig.Data]
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
	if channels[sig.Which] != nil {
		channels[sig.Which] <- sig.Data
		signalCollectMetrics(&sig, "received")
	}
}

// MuteChannel tells to not send any new events to a particular channel
// for a given signal.
func MuteChannel(signal int) error {
	if signal != SignalNatFillUp {
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
	if signal != SignalNatFillUp {
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
	if signal >= SignalTypeMax {
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
		signalMap, err := ebpf.LoadPinnedMap(path)
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
