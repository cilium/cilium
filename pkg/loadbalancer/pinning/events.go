// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import "github.com/cilium/stream"

type ObservableLbPinMapUpdateEvent stream.Observable[LbPinMapUpdateEvent]
type lbPinMapUpdateEventEmitter func(LbPinMapUpdateEvent)

type lbPinMapEventStream struct {
	observable ObservableLbPinMapUpdateEvent
	emitter    lbPinMapUpdateEventEmitter
	complete   func(error)
}

func newLbPinMapEventStream() *lbPinMapEventStream {
	src, emit, complete := stream.Multicast[LbPinMapUpdateEvent]()

	return &lbPinMapEventStream{
		observable: src,
		emitter:    emit,
		complete:   complete,
	}
}

func newLbPinMapEventObservable(s *lbPinMapEventStream) ObservableLbPinMapUpdateEvent {
	return s.observable
}
