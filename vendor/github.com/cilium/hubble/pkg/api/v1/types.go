// Copyright 2019 Authors of Hubble
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

package v1

import (
	"net"
	"sync"
	"time"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/gogo/protobuf/types"
)

// Endpoint is the representation of an endpoint running in the Cilium agent
type Endpoint struct {
	Created      time.Time  `json:"created"`
	Deleted      *time.Time `json:"deleted"`
	ContainerIDs []string   `json:"container-ids"`
	ID           uint64     `json:"id"`
	IPv4         net.IP     `json:"ipv4"`
	IPv6         net.IP     `json:"ipv6"`
	PodName      string     `json:"pod-name"`
	PodNamespace string     `json:"pod-namespace"`
	Labels       []string   `json:"labels"`
}

// Event represents a single event observed and stored by Hubble
type Event struct {
	// Timestamp when event was observed in Hubble
	Timestamp *types.Timestamp
	// Event contains the actual event
	Event interface{}
}

// GetFlow returns the decoded flow, or nil if there is no event
func (ev *Event) GetFlow() Flow {
	if ev == nil || ev.Event == nil {
		// returns typed nil so getter methods still work
		return (*pb.Flow)(nil)
	}
	if f, ok := ev.Event.(Flow); ok {
		return f
	}
	return nil
}

// Endpoints is a slice of endpoints and their cached dns queries protected by a mutex.
type Endpoints struct {
	mutex sync.RWMutex
	eps   []*Endpoint
}

// NewEndpoints returns a new *Endpoints.
func NewEndpoints() *Endpoints {
	return &Endpoints{
		eps: []*Endpoint{},
	}
}
