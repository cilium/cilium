// Copyright 2018-2019 Authors of Cilium
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

package annotation

const (
	// Prefix is the common prefix for all annotations
	Prefix = "io.cilium"

	// Name is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	Name = Prefix + ".name"

	// V4CIDRName is the annotation name used to store the IPv4
	// pod CIDR in the node's annotations.
	V4CIDRName = Prefix + ".network.ipv4-pod-cidr"
	// V6CIDRName is the annotation name used to store the IPv6
	// pod CIDR in the node's annotations.
	V6CIDRName = Prefix + ".network.ipv6-pod-cidr"

	// V4HealthName is the annotation name used to store the IPv4
	// address of the cilium-health endpoint in the node's annotations.
	V4HealthName = Prefix + ".network.ipv4-health-ip"
	// V6HealthName is the annotation name used to store the IPv6
	// address of the cilium-health endpoint in the node's annotations.
	V6HealthName = Prefix + ".network.ipv6-health-ip"

	// CiliumHostIP is the annotation name used to store the IPv4 address
	// of the cilium host interface in the node's annotations.
	CiliumHostIP = Prefix + ".network.ipv4-cilium-host"

	// CiliumHostIPv6 is the annotation name used to store the IPv6 address
	// of the cilium host interface in the node's annotation.
	CiliumHostIPv6 = Prefix + ".network.ipv6-cilium-host"

	// CiliumEncryptionKey is the annotation name used to store the encryption
	// key of the cilium host interface in the node's annotation.
	CiliumEncryptionKey = Prefix + ".network.encryption-key"

	// GlobalService if set to true, marks a service to become a global
	// service
	GlobalService = Prefix + "/global-service"

	// SharedService if set to false, prevents a service from being shared,
	// the default is true if GlobalService is set, otherwise false,
	// Setting the annotation SharedService to false while setting
	// GlobalService to true allows to expose remote endpoints without
	// sharing local endpoints.
	SharedService = Prefix + "/shared-service"

	// ProxyVisibility is the annotation name used to indicate whether proxy
	// visibility should be enabled for a given pod (i.e., all traffic for the
	// pod is redirected to the proxy for the given port / protocol in the
	// annotation
	ProxyVisibility = Prefix + ".proxy-visibility"

	// NoTrack is the annotation name used to store the port and protocol
	// that we should bypass kernel conntrack for a given pod. This applies for
	// both TCP and UDP connection. Current use case is NodeLocalDNS.
	NoTrack = Prefix + ".no-track-port"

	// WireguardPubKey is the annotation name used to store the Wireguard
	// public key in the CiliumNode CRD that we need to use to encrypt traffic
	// to that node.
	WireguardPubKey = Prefix + ".network.wg-pub-key"
)
