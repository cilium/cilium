// Copyright 2018-2019 Authors of Cilium
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

package hubble

import (
	"github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/server"
	"github.com/gogo/protobuf/types"

	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/node"
)

type hubbleListener struct {
	observer server.GRPCServer
}

// NewHubbleListener returns an initialized pointer to hubbleListener.
func NewHubbleListener(observer server.GRPCServer) listener.MonitorListener {
	ml := &hubbleListener{observer}
	return ml
}

// Enqueue converts monitor payload to the format accepted by Hubble:
//   https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/api/v1/flow/flow.proto#L266
func (ml *hubbleListener) Enqueue(pl *payload.Payload) {
	grpcPl := &flow.Payload{
		Data:     pl.Data,
		CPU:      int32(pl.CPU),
		Lost:     pl.Lost,
		Type:     flow.EventType(pl.Type),
		Time:     types.TimestampNow(),
		HostName: node.GetName(),
	}
	select {
	case ml.observer.GetEventsChannel() <- grpcPl:
	default:
		ml.observer.GetLogger().Debug("Per listener queue is full, dropping message")
	}
}

// Version returns the listener version supported by hubbleListener.
func (ml *hubbleListener) Version() listener.Version {
	return listener.Version1_2
}

// Close is a no-op for hubbleListener.
func (ml *hubbleListener) Close() {
}
