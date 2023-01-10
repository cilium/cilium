// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// IstioNodeToIP extract the IP address from an Envoy node identifier
// configured by Istio's pilot-agent.
//
// Istio's pilot-agent structures the nodeId as the concatenation of the
// following parts separated by ~:
//
// - node type: one of "sidecar", "ingress", or "router"
// - node IP address
// - node ID: the unique platform-specific sidecar proxy ID
// - node domain: the DNS domain suffix for short hostnames, e.g. "default.svc.cluster.local"
//
// For instance:
//
//	"sidecar~10.1.1.0~v0.default~default.svc.cluster.local"
func IstioNodeToIP(nodeId string) (string, error) {
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
