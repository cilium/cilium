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
	"runtime"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	SignalMapName = "cilium_signals"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "signal")

	config = bpf.PerfEventConfig{
		MapName:      SignalMapName,
		Type:         bpf.PERF_TYPE_SOFTWARE,
		Config:       bpf.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   bpf.PERF_SAMPLE_RAW,
		NumPages:     2,
		WakeupEvents: 1,
	}

	events *bpf.PerCpuEvents
)

func signalReceive(msg *bpf.PerfEventSample, cpu int) {
	log.Info("XXX Receive!!!")
}

func signalLost(lost *bpf.PerfEventLost, cpu int) {
}

func signalError(err *bpf.PerfEvent) {
}

func MuteSignalListener() {
	events.Mute()
}

func UnmuteSignalListener() {
	events.Unmute()
}

// StartSignalListener starts the go routine to process signals from BPF
// datapath in the kernel.
func StartSignalListener(wakeup chan<- int) {
	var err error

	config.NumCpus = runtime.NumCPU()

	events, err = bpf.NewPerCpuEvents(&config)
	if err != nil {
		log.WithError(err).Warningf("Cannot open %s map! Ignoring signals!",
			SignalMapName)
		return
	}

	go func() {
		log.Info("Signal listener up and running!")
		for {
			todo, err := events.Poll(-1)
			if err != nil {
				log.WithError(err).Warningf("%s poll error!",
					SignalMapName)
				continue
			}
			if todo > 0 {
				events.ReadAll(signalReceive, signalLost, signalError)
				wakeup <- 1
			}
		}
	}()
}
