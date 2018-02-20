// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"errors"
	"fmt"
	"net"
	"strings"

	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
)

// NodeToIDFunc extracts a string identifier from an Envoy Node identifier.
type NodeToIDFunc func(node *envoy_api_v2_core.Node) (string, error)

// IstioNodeToIP extract the IP address from an Envoy node identifier
// configured by Istio's pilot-agent.
//
// Istio's pilot-agent structures the node.id as the concatenation of the
// following parts separated by ~:
//
// - node type: one of "sidecar", "ingress", or "router"
// - node IP address
// - node ID: the unique platform-specific sidecar proxy ID
// - node domain: the DNS domain suffix for short hostnames, e.g. "default.svc.cluster.local"
//
// For instance:
//
//    "sidecar~10.1.1.0~v0.default~default.svc.cluster.local"
func IstioNodeToIP(node *envoy_api_v2_core.Node) (string, error) {
	if node == nil {
		return "", errors.New("node is nil")
	}
	if node.GetId() == "" {
		return "", errors.New("node.id is empty")
	}

	parts := strings.Split(node.Id, "~")
	if len(parts) != 4 {
		return "", fmt.Errorf("node.id is invalid: %s", node.Id)
	}

	ip := parts[1]

	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("node.id contains an invalid node IP address: %s", node.Id)
	}

	return ip, nil
}
