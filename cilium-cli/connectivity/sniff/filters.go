// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sniff

import (
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// GetTunnelFilter returns a tcpdump filter which captures encapsulated packets.
//
// The filter `(udp and port tunnelPort)` leverages tunnelPort, which is retrieved from
// the ConfigMap, and set to the default values in case `tunnel-port` is not specified.
func GetTunnelFilter(ct *check.ConnectivityTest) (string, error) {
	tunnelProtocol := ct.Features[features.Tunnel]
	tunnelPort := ct.Features[features.TunnelPort]

	if !tunnelProtocol.Enabled {
		return "", fmt.Errorf("tunnel-protocol disabled")
	}

	if tunnelPort.Mode == "" {
		return "", fmt.Errorf("empty tunnel-port for protocol %s", tunnelProtocol.Mode)
	}

	switch tunnelProtocol.Mode {
	case "vxlan", "geneve":
		return fmt.Sprintf("(udp and dst port %s)", tunnelPort.Mode), nil
	}

	return "", fmt.Errorf("unrecognized tunnel protocol %s", tunnelProtocol.Mode)
}
