// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	// PprofPort is the default port for pprof to listen on.
	PprofPort = 6062
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
