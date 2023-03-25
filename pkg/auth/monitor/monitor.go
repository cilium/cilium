// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type AuthManager interface {
	AuthRequired(*monitor.DropNotify, *monitor.ConnectionInfo)
}

// dropMonitor implements MonitorConsumer to listen on datapath drop notifications
type dropMonitor struct {
	authManager AuthManager
	lostEvents  uint64
	shutdown    chan struct{}
	queue       chan dropEvent
	logLimiter  logging.Limiter
}

type dropEvent struct {
	data []byte
}

func New(auth AuthManager, monitorQueueSize int) *dropMonitor {
	return &dropMonitor{
		authManager: auth,
		shutdown:    make(chan struct{}),
		queue:       make(chan dropEvent, monitorQueueSize),
		logLimiter:  logging.NewLimiter(10*time.Second, 3),
	}
}

func (dm *dropMonitor) NotifyAgentEvent(typ int, message interface{}) {
	// Not interested in agent events
}

func (dm *dropMonitor) NotifyPerfEvent(data []byte, cpu int) {
	if len(data) < monitor.DropNotifyLen || data[0] != monitorAPI.MessageTypeDrop || data[1] != byte(flow.DropReason_AUTH_REQUIRED) {
		// Event was not AUTH_REQUIRED
		return
	}

	dm.enqueueDropEvent(dropEvent{data: data})
}

func (dm *dropMonitor) enqueueDropEvent(evt dropEvent) {
	select {
	case <-dm.shutdown:
		// early return if shutting down
		return
	default:
	}

	select {
	case dm.queue <- evt:
		// successfully enqueued event in sink
		log.Debug("auth: successfully enqueued drop event for authentication")
	default:
		// queue full -> silently drop auth request to prevent blocking
		if dm.logLimiter.Allow() {
			log.Warningf("auth: failed to enqueue drop event due to filled queue")
		}
	}
}

func (dm *dropMonitor) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	dm.lostEvents += numLostEvents
}

func (dm *dropMonitor) startEventProcessing() {
	go func() {
		for {
			select {
			case evt := <-dm.queue:
				dn, ci, err := parse(evt.data)
				if err != nil {
					log.WithError(err).Warning("failed to process event")
					return
				}
				dm.authManager.AuthRequired(dn, ci)
			case <-dm.shutdown:
				return
			}
		}
	}()
}

// parse extracts drop notify event and connection information from received bytes.
func parse(data []byte) (*monitor.DropNotify, *monitor.ConnectionInfo, error) {
	dn := &monitor.DropNotify{}
	if err := binary.Read(bytes.NewReader(data), byteorder.Native, dn); err != nil {
		return nil, nil, errors.New("failed to parse drop notify")
	}

	// Packet data starts right after the DropNotify
	connInfo := monitor.GetConnectionInfo(data[monitor.DropNotifyLen:])

	return dn, connInfo, nil
}

func (dm *dropMonitor) stopEventProcessing() {
	close(dm.shutdown)
}

func (dm *dropMonitor) OnStart(startCtx hive.HookContext) error {
	dm.startEventProcessing()
	return nil
}

func (dm *dropMonitor) OnStop(stopCtx hive.HookContext) error {
	dm.stopEventProcessing()
	return nil
}
