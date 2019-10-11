// Copyright 2019 Authors of Cilium
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
	"runtime"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// SignalMapName is the BPF map name
	SignalMapName = "cilium_signals"
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

	config = bpf.PerfEventConfig{
		MapName:      SignalMapName,
		Type:         bpf.PERF_TYPE_SOFTWARE,
		Config:       bpf.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   bpf.PERF_SAMPLE_RAW,
		NumPages:     1,
		WakeupEvents: 1,
	}

	channels [SignalTypeMax]chan<- SignalData
)

func signalReceive(msg *bpf.PerfEventSample, cpu int) {
	sig := SignalMsg{}
	if err := binary.Read(bytes.NewReader(msg.DataDirect()), byteorder.Native, &sig); err != nil {
		log.WithError(err).Warningf("Cannot parse signal from BPF datapath")
		return
	}
	if channels[sig.Which] != nil {
		channels[sig.Which] <- sig.Data
	}
}

func signalLost(lost *bpf.PerfEventLost, cpu int) {
	// Not much we can do here, with the given set of signals it is non-fatal,
	// so we keep ignoring lost events right now.
}

func signalError(err *bpf.PerfEvent) {
	log.Errorf("BUG: Timeout while reading signal perf ring buffer: %s", err.Debug())
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
		events.Mute()
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
		events.Unmute()
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

var once sync.Once
var events *bpf.PerCpuEvents

// SetupSignalListener bootstraps signal listener infrastructure.
func SetupSignalListener() {
	once.Do(func() {
		var err error
		config.NumCpus = runtime.NumCPU()
		events, err = bpf.NewPerCpuEvents(&config)
		if err != nil {
			log.WithError(err).Warningf("Cannot open %s map! Ignoring signals!",
				SignalMapName)
			return
		}

		go func() {
			log.Info("Datapath signal listener running")
			for {
				todo, err := events.Poll(-1)
				if err != nil {
					log.WithError(err).Warningf("%s poll error!",
						SignalMapName)
					continue
				}
				if todo > 0 {
					events.ReadAll(signalReceive, signalLost, signalError)
				}
			}
		}()
	})
}
