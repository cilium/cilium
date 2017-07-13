// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/bpfdebug"
	"github.com/cilium/cilium/pkg/byteorder"

	log "github.com/Sirupsen/logrus"
)

func (d *Daemon) receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	data := msg.DataDirect()
	if data[0] == bpfdebug.MessageTypeDrop {
		dn := bpfdebug.DropNotify{}
		if err := binary.Read(bytes.NewReader(data), byteorder.Native, &dn); err != nil {
			log.Warningf("Error while parsing drop notification message: %s\n", err)
			return
		}
	}
}

func (d *Daemon) lostEvent(msg *bpf.PerfEventLost, cpu int) {
}

// EnableMonitor is used by the daemon to turn on the traffic monitoring.
func (d *Daemon) EnableMonitor() {
	startChan := make(chan bool, 1)
	stopChan1 := make(chan bool, 1)
	eventStopped := make(chan bool, 1)

	go func() {
		var events *bpf.PerCpuEvents
		var err error
		for {
			select {
			case <-startChan:
				log.Info("Starting monitoring traffic")
				events, err = bpf.NewPerCpuEvents(bpf.DefaultPerfEventConfig())
				if err != nil {
					log.Errorf("Error while starting monitor")
				}
				go func() {
					for {
						todo, err := events.Poll(5000)
						if err != nil {
							select {
							case <-eventStopped:
								log.Info("Monitor successfully stopped")
								return
							case <-time.Tick(time.Millisecond * 10):
								log.Error(err)
								return
							}
						}
						if todo > 0 {
							if err := events.ReadAll(d.receiveEvent, d.lostEvent); err != nil {
								log.Warningf("Error received while reading from perf buffer: %s", err)
							}
						}
					}
				}()
			case <-stopChan1:
				log.Info("Stopping monitor...")
				events.CloseAll()
				eventStopped <- true
			}
		}
	}()

}
