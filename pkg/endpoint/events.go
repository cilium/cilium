// Copyright 2019 Authors of Cilium
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

package endpoint

// TODO convert this to interface with a 'Run' function.
// Run function would measure time, return a channel which would be closed if
// the run function was done. Kill it with a context possibly.
// How do we handle blocks that run in parallel?
type EndpointEvent struct {
	EndpointEventMetadata interface{}
	EventResults          chan interface{}
	// Cancelled is a channel which is called when the EventQueue is being drained.
	Cancelled chan struct{}
}

func NewEndpointEvent(meta interface{}) *EndpointEvent {
	return &EndpointEvent{
		EndpointEventMetadata: meta,
		EventResults:          make(chan interface{}, 1),
		Cancelled:             make(chan struct{}),
	}
}

type EndpointRegenerationEvent struct {
	owner        Owner
	regenContext *regenerationContext
}

type EndpointRegenerationResult struct {
	err error
}

type EndpointRevisionBumpEvent struct {
	Rev uint64
}
