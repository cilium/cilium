// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"time"

	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
)

const (
	// ServerPort is the default port for hubble server when a provided
	// listen address does not include one.
	ServerPort = 4244

	// RelayPort is the default port for the hubble-relay server.
	RelayPort = 4245

	// GRPCServiceName is the name of the Hubble gRPC service.
	GRPCServiceName = "hubble-grpc"

	// GRPCMetadataServerVersionKey is the grpc metadata key for the Hubble server version.
	GRPCMetadataServerVersionKey = "hubble-server-version"

	// DomainName specifies the domain name to use when constructing the server
	// name for peer change notifications.
	DomainName = "cilium.io"

	// SensitiveValueRedacted is the string constant that is used to redact
	// sensitive information.
	SensitiveValueRedacted = "HUBBLE_REDACTED"

	// SocketPath is the path to the UNIX domain socket exposing the Hubble API
	// to clients locally.
	SocketPath = ciliumDefaults.RuntimePath + "/hubble.sock"

	// LostEventSendInterval is the default interval at which lost events are sent
	// from the Observer server, if any. The default of 1s matches Hubble
	// Relay's SortBufferDrainTimeout.
	LostEventSendInterval = 1 * time.Second
)
