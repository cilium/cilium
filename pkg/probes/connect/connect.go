// Copyright 2018 Authors of Cilium
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

package connect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/probes/api"
	"github.com/cilium/cilium/pkg/process"

	"github.com/iovisor/gobpf/bcc"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "connectProbe")
)

type connectProbe struct {
	api.ProbeProg

	connectEventsMap *bcc.PerfMap
	commEventsMap    *bcc.PerfMap
}

const (
	taskCommLen = 16

	typeEnter  = uint16(1)
	typeReturn = uint16(2)
)

type connectEvent struct {
	ProcessID          uint32
	SourceAddress      uint32
	DestinationAddress uint32
	DestinationPort    uint16
	Typ                api.ProbeType // uint16
	SocketAddress      uint64
}

type commEvent struct {
	ProcessID uint32
	Typ       api.ProbeType // uint16
	_         uint16
	Command   [taskCommLen]byte
}

func (c *connectProbe) OnAttach() error {
	log.Debug("Attaching connect kprobe")

	table := bcc.NewTable(c.Module.TableId("connect_events"), c.Module)
	connectEvents := make(chan []byte)

	connectEventsMap, err := bcc.InitPerfMap(table, connectEvents)
	if err != nil {
		return fmt.Errorf("failed to init perf map: %s\n", err)
	}

	table = bcc.NewTable(c.Module.TableId("comm_events"), c.Module)
	commEvents := make(chan []byte)

	commEventsMap, err := bcc.InitPerfMap(table, commEvents)
	if err != nil {
		return fmt.Errorf("failed to init perf map: %s\n", err)
	}

	c.connectEventsMap = connectEventsMap
	c.commEventsMap = commEventsMap

	go func() {
		for {
			process.Cache.Dump(os.Stdout)
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		var event connectEvent
		for {
			data := <-connectEvents
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.WithError(err).Warn("Failed to decode received data")
				continue
			}

			context, err := process.Cache.LookupOrCreate(process.PID(event.ProcessID))
			if err != nil {
				// XXX: Short-lived processes often hit this,
				//      They race and exit before we handle
				//      this event from the kernel.
				log.WithError(err).WithFields(logrus.Fields{
					logfields.PID: event.ProcessID,
				}).Debug("Cannot cache process from connect hook")
				continue
			}
			context.AddConnectEvent(process.ConnectContext{
				SrcIP:   ip.ParseUint32(event.SourceAddress),
				DstIP:   ip.ParseUint32(event.DestinationAddress),
				DstPort: byteorder.NetworkToHost(event.DestinationPort).(uint16),
				Socket:  event.SocketAddress,
			})
		}
	}()

	c.connectEventsMap.Start()

	go func() {
		var event commEvent
		for {
			data := <-commEvents
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.WithError(err).Warn("Failed to decode received data")
				continue
			}

			pid := process.PID(event.ProcessID)
			switch event.Typ {
			case api.KProbeType:
				context, err := process.Cache.LookupOrCreate(pid)
				if err != nil {
					log.WithError(err).WithFields(logrus.Fields{
						logfields.PID: event.ProcessID,
					}).Warning("Cannot cache process from comm hook")
					continue
				}
				context.AddExecveEvent(strings.TrimRight(string(event.Command[:taskCommLen]), "\x00"))
			// TODO: sys_exit() doesn't seem reliable.
			case api.KRetProbeType:
				process.Cache.Delete(pid)
			}
		}
	}()

	c.commEventsMap.Start()

	return nil
}

func (c *connectProbe) OnDetach() {
	log.Debug("Detaching connect kprobe...")
	c.commEventsMap.Stop()
	c.connectEventsMap.Stop()
	log.Debug("Detached connect kprobe")
}

func init() {
	api.Register(&connectProbe{
		ProbeProg: api.ProbeProg{
			SourceFilename: "kprobe_connect.c",
			Probes: []api.ProbeAttachment{
				{
					Typ:       api.KProbeType,
					FuncName:  "kprobe__tcp_v4_connect",
					ProbeName: "tcp_v4_connect",
				},
				{
					Typ:       api.KRetProbeType,
					FuncName:  "kretprobe__tcp_v4_connect",
					ProbeName: "tcp_v4_connect",
				},
				{
					Typ:       api.KProbeType,
					FuncName:  "syscall__execve",
					ProbeName: bcc.GetSyscallFnName("execve"),
				},
				{
					Typ:       api.KProbeType,
					FuncName:  "syscall__exit",
					ProbeName: bcc.GetSyscallFnName("exit"),
				},
			},
		},
	})
}
