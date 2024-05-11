// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signals

type Signal struct {
	Signal chan struct{}
}

func NewSignal() *Signal {
	return &Signal{
		Signal: make(chan struct{}, 1),
	}
}

// Event adds an edge triggered event to the Signal.
//
// A controller which uses this Signal will be notified of this event some
// time after.
//
// This signature adheres to the common event handling signatures of
// cache.ResourceEventHandlerFuncs for convenience.
func (s Signal) Event(_ interface{}) {
	select {
	case s.Signal <- struct{}{}:
	default:
	}
}
