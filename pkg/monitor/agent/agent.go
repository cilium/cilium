// Copyright 2017-2019 Authors of Cilium
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

package agent

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "monitor-agent")
)

// buildServer opens a listener socket at path. It exits with logging on all
// errors.
func buildServer(path string) (net.Listener, error) {
	os.Remove(path)
	server, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on unix socket %s: %s", path, err)
	}

	if os.Getuid() == 0 {
		err := api.SetDefaultPermissions(path)
		if err != nil {
			return nil, fmt.Errorf("cannot set default permissions on socket %s: %s", path, err)
		}
	}

	return server, nil
}

// Agent represents an instance of a monitor agent. It runs a monitor to read
// events from the BPF perf ring buffer and provides an interface to also pass
// in non-BPF events.
type Agent struct {
	mutex     lock.Mutex
	server1_2 net.Listener
	monitor   *Monitor
	queue     chan payload.Payload
}

// NewAgent creates a new monitor agent
func NewAgent(ctx context.Context, npages int) (a *Agent, err error) {
	a = &Agent{
		queue: make(chan payload.Payload, option.Config.MonitorQueueSize),
	}

	a.server1_2, err = buildServer(defaults.MonitorSockPath1_2)
	if err != nil {
		return
	}

	a.monitor, err = NewMonitor(ctx, npages, a.server1_2)
	if err != nil {
		return
	}

	log.Infof("Serving cilium node monitor v1.2 API at unix://%s", defaults.MonitorSockPath1_2)

	go a.eventDrainer()

	return
}

// Stop stops the monitor agent
func (a *Agent) Stop() {
	a.server1_2.Close()
	close(a.queue)
}

func (a *Agent) eventDrainer() {
	for {
		p, ok := <-a.queue
		if !ok {
			return
		}

		a.monitor.send(&p)
	}
}

// State returns the monitor status.
func (a *Agent) State() *models.MonitorStatus {
	if a == nil || a.monitor == nil {
		return nil
	}

	return a.monitor.Status()
}

// SendEvent sends an event to the node monitor which will then distribute to
// all monitor listeners
func (a *Agent) SendEvent(typ int, event interface{}) error {
	var buf bytes.Buffer

	if a == nil {
		return fmt.Errorf("monitor agent is not set up")
	}

	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		//nm.bumpLost()
		return fmt.Errorf("Unable to gob encode: %s", err)
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	p := payload.Payload{Data: append([]byte{byte(typ)}, buf.Bytes()...), CPU: 0, Lost: 0, Type: payload.EventSample}

	select {
	case a.queue <- p:
	default:
		//nm.bumpLost()
		return fmt.Errorf("Monitor queue is full, discarding notification")
	}

	return nil
}

// GetMonitor returns the pointer to the monitor.
func (a *Agent) GetMonitor() *Monitor {
	return a.monitor
}
