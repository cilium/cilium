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

// SecurityIDContexts maps a security identity to a L4RuleContexts.
// The security identity used as a key is a source of flows (e.g. the source
// of a TCP connection).
// The L4RuleContexts is a whitelist of the flows allowed from that security
// identity at ingress and egress.
type SecurityIDContexts map[identity.NumericIdentity]L4RuleContexts

// DeepCopy returns a deep copy of SecurityIDContexts
func (sc SecurityIDContexts) DeepCopy() SecurityIDContexts {
	cpy := make(SecurityIDContexts, len(sc))
	for k, v := range sc {
		cpy[k] = v.DeepCopy()
	}
	return cpy
}

// SecurityIDContexts returns a new L4RuleContexts created.
func NewSecurityIDContexts() SecurityIDContexts {
	return SecurityIDContexts(make(map[identity.NumericIdentity]L4RuleContexts))
}

// L4RuleContexts maps a rule context to a L7RuleContext.
type L4RuleContexts map[L4RuleContext]L7RuleContext

// NewL4RuleContexts returns a new L4RuleContexts.
func NewL4RuleContexts() L4RuleContexts {
	return L4RuleContexts(make(map[L4RuleContext]L7RuleContext))
}

// DeepCopy returns a deep copy of L4RuleContexts
func (rc L4RuleContexts) DeepCopy() L4RuleContexts {
	cpy := make(L4RuleContexts, len(rc))
	for k, v := range rc {
		cpy[k] = v
	}
	return cpy
}

// IsL3Only returns false if the given L4RuleContexts contains any entry. If it
// does not contain any entry it is considered an L3 only rule.
func (rc L4RuleContexts) IsL3Only() bool {
	return rc != nil && len(rc) == 0
}

// L4RuleContext represents a L4 rule.
// Don't use pointers here since this structure is used as key on maps.
type L4RuleContext struct {
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
func (rc L4RuleContext) ProxyID() string {
	proto := u8proto.U8proto(rc.Proto).String()
	port := byteorder.NetworkToHost(rc.Port).(uint16)
	return ProxyID(rc.EndpointID, rc.Ingress, proto, port)
}

// PortProto returns the port-proto tuple in a human readable format. i.e.
// with its port in host byte order.
func (rc L4RuleContext) PortProto() string {
	proto := u8proto.U8proto(rc.Proto).String()
	port := strconv.Itoa(int(byteorder.NetworkToHost(uint16(rc.Port)).(uint16)))
	return port + "/" + proto
}

// L7RuleContext represents a L7 rule
type L7RuleContext struct {
	// RedirectPort is the L7 redirect port in the policy in network byte order.
	RedirectPort uint16
	// L4Installed specifies if the L4 rule is installed in the L4 BPF map.
	L4Installed bool
}

// IsRedirect checks if the L7RuleContext is a redirect to the proxy.
func (rc L7RuleContext) IsRedirect() bool {
	return rc.RedirectPort != 0
}
