// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// EnvoyNodeIdToIP extracts the IP address from an Envoy node identifier.
//
// The NodeID is structured as the concatenation of the
// following parts separated by ~:
//
// - node type
// - node IP address
// - node ID
// - node domain: the DNS domain suffix for short hostnames, e.g. "default.svc.cluster.local"
//
// For instance:
//
//	"host~127.0.0.1~no-id~localdomain"
func EnvoyNodeIdToIP(nodeId string) (string, error) {
	if nodeId == "" {
		return "", errors.New("nodeId is empty")
	}

	parts := strings.Split(nodeId, "~")
	if len(parts) != 4 {
		return "", fmt.Errorf("nodeId is invalid: %s", nodeId)
	}

	ip := parts[1]

	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("nodeId contains an invalid node IP address: %s", nodeId)
	}

	return ip, nil
}
