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
	return fmt.Sprintf("%s:%s:%d:%d", direction, protocol, port, proxyPort)
}

// ProxyID returns a unique string to identify a proxy mapping.
func ProxyID(endpointID uint16, ingress bool, protocol string, port uint16, parser L7ParserType, listener string) string {
	direction := "egress"
	if ingress {
		direction = "ingress"
	}
	return fmt.Sprintf("%d:%s:%s:%d:%s:%s", endpointID, direction, protocol, port, parser, listener)
}

// ProxyIDFromKey returns a unique string to identify a proxy mapping.
func ProxyIDFromKey(endpointID uint16, key Key, parser L7ParserType, listener string) string {
	return ProxyID(endpointID, key.TrafficDirection == trafficdirection.Ingress.Uint8(), u8proto.U8proto(key.Nexthdr).String(), key.DestPort, parser, listener)
}

// ParseProxyID parses a proxy ID returned by ProxyID and returns its components.
func ParseProxyID(proxyID string) (endpointID uint16, ingress bool, protocol string, port uint16, parser L7ParserType, listener string, err error) {
	comps := strings.Split(proxyID, ":")
	if len(comps) != 6 {
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
	parser = L7ParserType(comps[4])
	listener = comps[5]
	return
}
