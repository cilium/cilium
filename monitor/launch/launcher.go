// Copyright 2017-2018 Authors of Cilium
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

package launch

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/launcher"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

const (
	targetName = "cilium-node-monitor"

	// queueSize is the size of the message queue
	queueSize = 524288

	// restartInterval is the delay between attempts to restart node-monitor
	restartInterval = time.Second
)

// NodeMonitor is used to wrap the node executable binary.
type NodeMonitor struct {
	launcher.Launcher

	state *models.MonitorStatus

	// The following members are protected by pipeLock
	pipeLock lock.Mutex
	pipe     *os.File
	lost     uint64
	lostLast uint64

	queue chan []byte
}

// NewNodeMonitor returns a new node monitor
func NewNodeMonitor() *NodeMonitor {
	nm := &NodeMonitor{
		queue: make(chan []byte, queueSize),
	}

	go nm.eventDrainer()

	return nm
}

// GetPid returns the node monitor's pid.
func (nm *NodeMonitor) GetPid() int {
	return nm.GetProcess().Pid
}

// Run starts the node monitor.
func (nm *NodeMonitor) Run(sockPath, bpfRoot string) {
	nm.SetTarget(targetName)
	for {
		os.Remove(sockPath)
		if err := syscall.Mkfifo(sockPath, 0600); err != nil {
			log.WithError(err).Fatalf("Unable to create named pipe %s", sockPath)
			time.Sleep(time.Duration(5) * time.Second)
		}

		pipe, err := os.OpenFile(sockPath, os.O_RDWR, 0600)
		if err != nil {
			log.WithError(err).Fatal("Unable to open named pipe for writing")
			time.Sleep(time.Duration(5) * time.Second)
		}

		nm.Mutex.Lock()
		nm.pipe = pipe
		nm.Mutex.Unlock()

		nm.Launcher.SetArgs([]string{"--bpf-root", bpfRoot})
		nm.Launcher.Run()

		r := bufio.NewReader(nm.GetStdout())
		for nm.GetProcess() != nil {
			l, _ := r.ReadBytes('\n') // this is a blocking read
			var tmp *models.MonitorStatus
			if err := json.Unmarshal(l, &tmp); err != nil {
				continue
			}
			nm.setState(tmp)
		}

		pipe.Close()

		// throttle breakage loops
		time.Sleep(restartInterval)
	}
}

// State returns the monitor status.
func (nm *NodeMonitor) State() *models.MonitorStatus {
	nm.Mutex.RLock()
	state := nm.state
	nm.Mutex.RUnlock()
	return state
}

// setState sets the internal state monitor with the given state.
func (nm *NodeMonitor) setState(state *models.MonitorStatus) {
	nm.Mutex.Lock()
	nm.state = state
	nm.Mutex.Unlock()
}

// SendEvent sends an event to the node monitor which will then distribute to
// all monitor listeners
func (nm *NodeMonitor) SendEvent(typ int, event interface{}) error {
	var buf bytes.Buffer

	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		nm.bumpLost()
		return fmt.Errorf("Unable to gob encode: %s", err)
	}

	select {
	case nm.queue <- append([]byte{byte(typ)}, buf.Bytes()...):
	default:
		nm.bumpLost()
		return fmt.Errorf("Monitor queue is full, discarding notification")
	}

	return nil
}

// bumpLost accounts for a lost notification
func (nm *NodeMonitor) bumpLost() {
	nm.pipeLock.Lock()
	nm.lost++
	nm.pipeLock.Unlock()
}

// lostSinceLastTime returns the number of lost samples since the last call to
// lostSinceLastTime(), the pipeLock must be held for writing.
func (nm *NodeMonitor) lostSinceLastTime() uint64 {
	delta := nm.lost - nm.lostLast
	nm.lostLast = nm.lost
	return delta
}

func (nm *NodeMonitor) eventDrainer() {
	for {
		if err := nm.send(<-nm.queue); err != nil {
			log.WithError(err).Warning("Unable to send monitor notification")
		}
	}
}

func (nm *NodeMonitor) send(data []byte) error {
	nm.pipeLock.Lock()
	defer nm.pipeLock.Unlock()

	if nm.pipe == nil {
		return fmt.Errorf("monitor pipe not opened")
	}

	p := payload.Payload{Data: data, CPU: 0, Lost: nm.lostSinceLastTime(), Type: payload.EventSample}

	buf, err := p.BuildMessage()
	if err != nil {
		return err
	}

	if _, err := nm.pipe.Write(buf); err != nil {
		nm.pipe.Close()
		nm.pipe = nil
		return fmt.Errorf("Unable to write message buffer to pipe: %s", err)
	}

	return nil
}
