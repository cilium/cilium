// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

// ProxyStatsKey returns a key for endpoint's proxy stats, which may aggregate stats from multiple
// proxy redirects on the same port.
func ProxyStatsKey(ingress bool, protocol string, port, proxyPort uint16) string {
	direction := "egress"
	if ingress {
		direction = "ingress"
	}
	portStr := strconv.FormatUint(uint64(port), 10)
	proxyPortStr := strconv.FormatUint(uint64(proxyPort), 10)

	var str strings.Builder
	str.Grow(len(direction) + 1 + len(protocol) + 1 + len(portStr) + 1 + len(proxyPortStr))
	str.WriteString(direction)
	str.WriteRune(':')
	str.WriteString(protocol)
	str.WriteRune(':')
	str.WriteString(portStr)
	str.WriteRune(':')
	str.WriteString(proxyPortStr)

	return str.String()
}

// ProxyID returns a unique string to identify a proxy mapping.
func ProxyID(endpointID uint16, ingress bool, protocol string, port uint16, listener string) string {
	direction := "egress"
	if ingress {
		direction = "ingress"
	}
	epStr := strconv.FormatUint(uint64(endpointID), 10)
	portStr := strconv.FormatUint(uint64(port), 10)

	var str strings.Builder
	str.Grow(len(epStr) + 1 + len(direction) + 1 + len(protocol) + 1 + len(portStr) + 1 + len(listener))
	str.WriteString(epStr)
	str.WriteRune(':')
	str.WriteString(direction)
	str.WriteRune(':')
	str.WriteString(protocol)
	str.WriteRune(':')
	str.WriteString(portStr)
	str.WriteRune(':')
	str.WriteString(listener)

	return str.String()
}

// ProxyIDFromKey returns a unique string to identify a proxy mapping.
func ProxyIDFromKey(endpointID uint16, key Key, listener string) string {
	return ProxyID(endpointID, key.TrafficDirection == trafficdirection.Ingress.Uint8(), u8proto.U8proto(key.Nexthdr).String(), key.DestPort, listener)
}

// ParseProxyID parses a proxy ID returned by ProxyID and returns its components.
func ParseProxyID(proxyID string) (endpointID uint16, ingress bool, protocol string, port uint16, listener string, err error) {
	comps := strings.Split(proxyID, ":")
	if len(comps) != 5 {
		err = fmt.Errorf("invalid proxy ID structure: %s", proxyID)
		return
	}
	epID, err := strconv.ParseUint(comps[0], 10, 16)
	if err != nil {
		return
	}
	endpointID = uint16(epID)
	ingress = comps[1] == "ingress"
	protocol = comps[2]
	l4port, err := strconv.ParseUint(comps[3], 10, 16)
	if err != nil {
		return
	}
	port = uint16(l4port)
	listener = comps[4]
	return
}
