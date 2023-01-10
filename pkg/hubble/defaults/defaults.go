// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

const (
	// ServerPort is the default port for hubble server when a provided
	// listen address does not include one.
	ServerPort = 4244

	// RelayPort is the default port for the hubble-relay server.
	RelayPort = 4245

	// GRPCServiceName is the name of the Hubble gRPC service.
	GRPCServiceName = "hubble-grpc"

	// DomainName specifies the domain name to use when constructing the server
	// name for peer change notifications.
	DomainName = "cilium.io"
)
