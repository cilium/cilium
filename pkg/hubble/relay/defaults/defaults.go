// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"fmt"
	"time"

	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	hubbleDefaults "github.com/cilium/cilium/pkg/hubble/defaults"
)

const (
	// ClusterName is the default cluster name
	ClusterName = ciliumDefaults.ClusterName
	// HealthCheckInterval is the time interval between health checks.
	HealthCheckInterval = 5 * time.Second
	// GopsPort is the default port for gops to listen on.
	GopsPort = 9893
	// PprofAddress is the default port for pprof to listen on.
	PprofAddress = "localhost"
	// PprofPort is the default port for pprof to listen on.
	PprofPort = 6062
	// RetryTimeout is the duration to wait between reconnection attempts.
	RetryTimeout = 30 * time.Second
	// PeerTarget is the address of the peer service.
	PeerTarget = "unix://" + hubbleDefaults.SocketPath
	// PeerServiceName is the name of the peer service, should it exist.
	PeerServiceName = "hubble-peer"

	// SortBufferMaxLen is the max number of flows that can be buffered for
	// sorting before being sen to the client.
	SortBufferMaxLen = 100
	// SortBufferDrainTimeout is the rate at which flows are drained from the
	// sorting buffer when it is not full.
	SortBufferDrainTimeout = 1 * time.Second
	// ErrorAggregationWindow is the time window during which errors with the
	// same message are coalesced.
	ErrorAggregationWindow = 10 * time.Second
	// PeerUpdateInterval is the time interval in which relay is checking for
	// newly joined peers for long running requests
	PeerUpdateInterval = 2 * time.Second

	// GRPCMetadataRelayVersionKey is the grpc metadata key for the Hubble relay server version.
	GRPCMetadataRelayVersionKey = "hubble-relay-version"
)

var (
	// ListenAddress is the address on which the Hubble Relay server listens
	// for incoming gRPC requests.
	ListenAddress = fmt.Sprintf(":%d", hubbleDefaults.RelayPort)

	// HealthListenAddress is the address on which the Hubble Relay gRPC health
	// server listens on
	HealthListenAddress = fmt.Sprintf(":%d", 4222)
)
