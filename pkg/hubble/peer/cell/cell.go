// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
)

// Cell provides the Hubble peer service that handles peer discovery and notifications.
var Cell = cell.Module(
	"hubble-peer-service",
	"Hubble peer service for handling peer discovery and notifications",

	cell.Provide(newPeerService),
)

// HubbleConfig contains the configuration needed by the peer service
type HubbleConfig struct {
	ListenAddress   string
	PreferIpv6      bool
	EnableServerTLS bool
}

type peerServiceParams struct {
	cell.In

	Logger      *slog.Logger
	Lifecycle   cell.Lifecycle
	NodeManager nodeManager.NodeManager
	Config      *HubbleConfig
	Health      cell.Health
}

// getPort extracts the port from an address string.
// Supports formats like ":4244", "localhost:4244", "[::1]:4244"
func getPort(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("parse host address and port: %w", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse port number: %w", err)
	}
	return portNum, nil
}

func newPeerService(params peerServiceParams) (*peer.Service, error) {
	var peerServiceOptions []serviceoption.Option

	// Determine if TLS is disabled
	if !params.Config.EnableServerTLS {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithoutTLSInfo())
	}

	// Set address family preference
	if params.Config.PreferIpv6 {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithAddressFamilyPreference(serviceoption.AddressPreferIPv6))
	}

	// Extract port from listen address if available
	if addr := params.Config.ListenAddress; addr != "" {
		port, err := getPort(addr)
		if err != nil {
			params.Health.Degraded(
				"Hubble server will not pass port information in change notifications on exposed Hubble peer service",
				err,
			)
			params.Logger.Warn(
				"Hubble server will not pass port information in change notifications on exposed Hubble peer service",
				logfields.Error, err,
				logfields.Address, addr,
			)
		} else {
			peerServiceOptions = append(peerServiceOptions, serviceoption.WithHubblePort(port))
		}
	}

	service := peer.NewService(params.NodeManager, peerServiceOptions...)

	// Register stop hook to properly close the peer service
	params.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			return service.Close()
		},
	})

	return service, nil
}
