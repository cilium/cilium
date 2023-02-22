// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
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
}

func New(auth AuthManager) *dropMonitor {
	return &dropMonitor{authManager: auth}
}

func (dm *dropMonitor) NotifyAgentEvent(typ int, message interface{}) {
	// Not interested in agent events
}

func (dm *dropMonitor) NotifyPerfEvent(data []byte, cpu int) {
	if len(data) < monitor.DropNotifyLen || data[0] != monitorAPI.MessageTypeDrop || data[1] != byte(flow.DropReason_AUTH_REQUIRED) {
		// Event was not AUTH_REQUIRED
		return
	}

	dn := &monitor.DropNotify{}
	if err := binary.Read(bytes.NewReader(data), byteorder.Native, dn); err != nil {
		log.WithError(err).Warning("failed to parse drop")
		return
	}

	// Packet data starts right after the DropNotify
	connInfo := monitor.GetConnectionInfo(data[unsafe.Sizeof(*dn):])

	dm.authManager.AuthRequired(dn, connInfo)
}

func (dm *dropMonitor) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	dm.lostEvents += numLostEvents
}
