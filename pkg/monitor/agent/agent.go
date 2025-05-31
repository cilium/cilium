// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
)

// isCtxDone is a utility function that returns true when the context's Done()
// channel is closed. It is intended to simplify goroutines that need to check
// this multiple times in their loop.
func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

type Agent interface {
	AttachToEventsMap(nPages int) error
	SendEvent(typ int, event any) error
	RegisterNewListener(newListener listener.MonitorListener)
	RemoveListener(ml listener.MonitorListener)
	RegisterNewConsumer(newConsumer consumer.MonitorConsumer)
	RemoveConsumer(mc consumer.MonitorConsumer)
	State() *models.MonitorStatus
}
