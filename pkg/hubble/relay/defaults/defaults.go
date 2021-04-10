// Copyright 2020 Authors of Cilium
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

package defaults

import (
	"fmt"
	"time"

	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	hubbledefaults "github.com/cilium/cilium/pkg/hubble/defaults"
)

const (
	// DialTimeout is the timeout that is used when establishing a new
	// connection.
	DialTimeout = 5 * time.Second
	// GopsPort is the default port for gops to listen on.
	GopsPort = 9893
	// RetryTimeout is the duration to wait between reconnection attempts.
	RetryTimeout = 30 * time.Second
	// HubbleTarget is the address of the local Hubble instance.
	HubbleTarget = "unix://" + ciliumDefaults.HubbleSockPath

	// SortBufferMaxLen is the max number of flows that can be buffered for
	// sorting before being sen to the client.
	SortBufferMaxLen = 100
	// SortBufferDrainTimeout is the rate at which flows are drained from the
	// sorting buffer when it is not full.
	SortBufferDrainTimeout = 1 * time.Second
	// ErrorAggregationWindow is the time window during which errors with the
	// same message are coalesced.
	ErrorAggregationWindow = 10 * time.Second
)

var (
	// ListenAddress is the address on which the Hubble Relay server listens
	// for incoming requests.
	ListenAddress = fmt.Sprintf(":%d", hubbledefaults.RelayPort)
)
