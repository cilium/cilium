// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/stretchr/testify/assert"
)

func Test_dropMonitor_NotifyPerfEventLost(t *testing.T) {
	dm := &dropMonitor{}
	assert.Equal(t, uint64(0), dm.lostEvents)

	dm.NotifyPerfEventLost(1, 0)
	assert.Equal(t, uint64(1), dm.lostEvents)

	dm.NotifyPerfEventLost(5, 0)
	assert.Equal(t, uint64(6), dm.lostEvents)
}

func Test_dropMonitor_NotifyPerfEvent_DontHandleOtherNotificationTypes(t *testing.T) {
	dm := &dropMonitor{}

	dn := &monitor.DropNotify{
		Type: monitorAPI.MessageTypeCapture,
	}

	buffer := bytes.NewBuffer([]byte{})
	err := binary.Write(buffer, byteorder.Native, dn)
	assert.NoError(t, err)

	dm.NotifyPerfEvent(buffer.Bytes(), 0)
}

func Test_dropMonitor_NotifyPerfEvent_DontHandleOtherDropSubTypes(t *testing.T) {
	dm := &dropMonitor{}

	dn := &monitor.DropNotify{
		Type:    monitorAPI.MessageTypeDrop,
		SubType: uint8(flow.DropReason_CT_MAP_INSERTION_FAILED),
	}

	buffer := bytes.NewBuffer([]byte{})
	err := binary.Write(buffer, byteorder.Native, dn)
	assert.NoError(t, err)

	dm.NotifyPerfEvent(buffer.Bytes(), 0)
}

func Test_dropMonitor_NotifyPerfEvent_AuthenticateDroppedPacketsWithAuthRequired(t *testing.T) {
	dn := &monitor.DropNotify{
		Type:     monitorAPI.MessageTypeDrop,
		SubType:  uint8(flow.DropReason_AUTH_REQUIRED),
		Source:   1,
		SrcLabel: identity.NumericIdentity(1),
		DstLabel: identity.NumericIdentity(2),
		DstID:    2,
		ExtError: 0, // Auth Type
	}

	mockAuthManager := &fakeAuthManager{}

	dm := &dropMonitor{authManager: mockAuthManager}

	buffer := bytes.NewBuffer([]byte{})
	err := binary.Write(buffer, byteorder.Native, dn)
	assert.NoError(t, err)

	dm.NotifyPerfEvent(buffer.Bytes(), 0)
}

type fakeAuthManager struct {
}

func (r *fakeAuthManager) AuthRequired(*monitor.DropNotify, *monitor.ConnectionInfo) {
}
