// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package signaler

// BGPCPSignaler multiplexes multiple event sources into a single level-triggered
// event instructing the BGP Control Plane Controller to perform reconciliation.
//
// BGPCPSignaler should always be constructed with a channel of size 1.
//
// Use of a BGPCPSignaler allows for bursts of events to be "rolled-up".
// This is a suitable approach since the Controller checks the entire state of
// the world on each iteration of its control loop.
//
// Additionally, this precludes any need for ordering between different event
// sources.
type BGPCPSignaler struct {
	Sig chan struct{}
}

// NewSignaler constructs a Signaler
func NewBGPCPSignaler() *BGPCPSignaler {
	return &BGPCPSignaler{
		Sig: make(chan struct{}, 1),
	}
}

// Event adds an edge triggered event to the Signaler.
//
// A controller which uses this Signaler will be notified of this event some
// time after.
//
// This signature adheres to the common event handling signatures of
// cache.ResourceEventHandlerFuncs for convenience.
func (s BGPCPSignaler) Event(_ interface{}) {
	select {
	case s.Sig <- struct{}{}:
	default:
	}
}
