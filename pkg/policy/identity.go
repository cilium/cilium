// Copyright 2016-2018 Authors of Cilium
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

package policy

import (
	"strconv"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"
)

// SecurityIdentityL4L7Map maps a security identity to an L4L7Map. This contains
// all policy-related information which has dependencies upon other layers of the protocol
// stack (the only exception to this is CIDR-related policy). An empty L4L7Map
// corresponds to a policy which is identity-based only.
type SecurityIdentityL4L7Map map[identity.NumericIdentity]L4L7Map

// DeepCopy returns a deep copy of SecurityIdentityL4L7Map.
func (sc SecurityIdentityL4L7Map) DeepCopy() SecurityIdentityL4L7Map {
	cpy := make(SecurityIdentityL4L7Map, len(sc))
	for k, v := range sc {
		cpy[k] = v.DeepCopy()
	}
	return cpy
}

// SecurityIdentityL4L7Map allocates and initializes an empty SecurityIdentityL4L7Map.
func NewSecurityIdentityL4L7Map() SecurityIdentityL4L7Map {
	return make(SecurityIdentityL4L7Map)
}

// L4L7Map maps L4 policy-related metadata with L7 policy-related metadata.
type L4L7Map map[L4Rule]L7Rule

// NewL4L7Map returns a new L4L7Map.
func NewL4L7Map() L4L7Map {
	return L4L7Map(make(map[L4Rule]L7Rule))
}

// DeepCopy returns a deep copy of L4L7Map.
func (rc L4L7Map) DeepCopy() L4L7Map {
	cpy := make(L4L7Map, len(rc))
	for k, v := range rc {
		cpy[k] = v
	}
	return cpy
}

// IsL3Only returns false if the given L4L7Map contains any entry. If it
// does not contain any entry it is considered an L3 only rule.
func (rc L4L7Map) IsL3Only() bool {
	return rc != nil && len(rc) == 0
}

// L4Rule represents an L4 rule.
// Do not use pointers for fields in this type since this structure is used as
// a key for maps.
type L4Rule struct {
	// EndpointID is the identity of the endpoint where this rule is enforced, in host byte order.
	EndpointID uint16
	// Ingress indicates whether the flow is an ingress rule (vs. egress).
	Ingress bool
	// Proto is the IP protocol of the flow.
	Proto uint8
	// Port is the destination port in the policy, in network byte order.
	Port uint16
}

// ProxyID return the proxy ID representation of this rule, in the same format
// as returned by Endpoint.ProxyID.
func (rc L4Rule) ProxyID() string {
	proto := u8proto.U8proto(rc.Proto).String()
	port := byteorder.NetworkToHost(rc.Port).(uint16)
	return ProxyID(rc.EndpointID, rc.Ingress, proto, port)
}

// String returns the port-protocol tuple in a human readable format, i.e.
// with its port in host-byte order.
func (rc L4Rule) String() string {
	proto := u8proto.U8proto(rc.Proto).String()
	port := strconv.Itoa(int(byteorder.NetworkToHost(uint16(rc.Port)).(uint16)))
	return port + "/" + proto
}

// L7Rule contains the L7-specific parts of a policy rule.
type L7Rule struct {
	// RedirectPort is the L7 redirect port in the policy in network byte order.
	RedirectPort uint16
	// L4Installed specifies if the L4 rule is installed in the L4 BPF map.
	L4Installed bool
}

// IsRedirect checks if the L7Rule has a non-zero redirect port. A non-zero
// redirect port means that traffic should be directed to the L7-proxy.
func (rc L7Rule) IsRedirect() bool {
	return rc.RedirectPort != 0
}
