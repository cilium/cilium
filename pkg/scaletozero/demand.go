// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"encoding/binary"
	"io"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	scaletozeromap "github.com/cilium/cilium/pkg/maps/scaletozero"
	"github.com/cilium/cilium/pkg/time"
)

// signalMetricData describes a scale-from-zero signal for the signals metric.
// The service is deliberately left out: it would become a metric label.
const signalMetricData = "wake"

// demandTracker turns the scale-from-zero signals emitted by the datapath into
// the per-service demand gauge. A signal is the only source of demand: it is
// sent once per new connection to a scale-to-zero service (rate limited per
// service by the datapath), so a service that was signalled recently is one
// somebody is trying to reach.
type demandTracker struct {
	// services resolves the datapath ID a signal carries back to the service
	// the reconciler tracked it for. Frontends expanded to a node address
	// exist only in the BPF maps, so this is the only complete mapping.
	services scaletozeromap.Map
	window   time.Duration
	demand   *serviceDemand
}

// handleWake is the [signal.SignalHandler] for SignalScaleFromZero.
func (t *demandTracker) handleWake(reader io.Reader) (string, error) {
	if reader == nil {
		// The signal manager is shutting down.
		return "", nil
	}

	var revNATIndex uint32
	if err := binary.Read(reader, binary.NativeEndian, &revNATIndex); err != nil {
		return "", err
	}
	// The datapath sends the service ID as it stores it, in network byte order.
	id := loadbalancer.ServiceID(byteorder.NetworkToHost16(uint16(revNATIndex)))

	name, found := t.services.Resolve(id)
	if !found {
		// The service opted out or was deleted after the signal was emitted,
		// or the agent has not finished its first reconciliation. Signals are
		// a hint that repeats while the demand lasts, so drop it and wait for
		// the next one.
		return signalMetricData, nil
	}
	t.demand.wake(name, t.window)

	return signalMetricData, nil
}
