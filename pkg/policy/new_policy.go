// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
)

type IdentityPolicy struct {
	Ingress DirectionalPolicy
	Egress  DirectionalPolicy
}

// DirectionalPolicy is the list of allowed identities described as label based
// selectors. If empty, no identities are whitelisted. In policy=always mode,
// this would drop everything, policy=auto and k8s mode, this will translate
// into default allow.
type DirectionalPolicy map[int]IdentityPortSelector // L3 allowed identities for ingress/egress.

type IdentityPortSelector struct {
	//  Port is the L4, if not set, all ports apply
	// +optional
	Port int

	// Porotocol is the L4 protocol, if not set, all protocols apply
	// +optional
	Protocol proto

	// L7 policy
	// +optional
	L7 L7Policy

	// AllowedIdentities is the list of referenced identity selectors.
	// Identity selectors are shared between all IdentityPolicy instances.
	//
	// The IdentitySelector pointer is used as a key. As duplicate usage of
	// the same IdentitySelector instances means that the identiy selector
	// is identical so the selection is guaranteed to be identical
	AllowedIdentities map[*IdentitySelector]AllowedIdentity

	// ContributingRules is the list of rule UUIDs that cause this identity
	// to be whitelisted
	ContributingRules []UUID
}

// AllowedIdentity contains an allow identity selector as whitelisted by one or
// more rules as selected by the IdentityPolicy which is owning this
// AllowedIdentity
type AllowedIdentity struct {
	PortSelector      *IdentityPortSelector
	ContributingRules []UUID
	Selector          *IdentitySelector
}

type L7Policy struct {
	ContributingRules []uuid
	Rules             interface{}
}

// --- ^^ incremental rule layer ^^ --

type IdentitySelector interface {
}

// IdentitySelector represents the mapping of an EndpointSelectorSlice to a
// slice of identities
type LabelIdentitySelector struct {
	Referals        map[*AllowedIdentity]struct{}
	Selector        EndpointSelectorSlice // incremental rule layer
	CachedSelection []*identity.Identity  // map to identity layer
}

type FQDNSelector struct {
	Referals        map[*AllowedIdentity]struct{}
	Selector        EndpointSelectorSlice         // fqdn:isovalent.com
	CachedSelection map[string]*identity.Identity // identity.String(): "cidr:1.1.1.1" -> identity of 1.1.1.1
}

// GetIdentitySelector returns the identity selector for a particular
// EndpointSelectorSlice. If an IdentitySelector with an identical
// EndpointSelectorSlice already exists, that IdentitySelector is returned, if
// it does not exist, it is created and added to the cache.
func GetIdentitySelector(selector EndpointSelectorSlice) *IdentitySelector {
	return nil
}

// Walk through
//
// endpoint 100 grp=blue,app=foo secid=10
// endpoint 200 grp=blue,app=bar secid=20
//
// Mutation-1 : Add the following rule UUID-1
// endpointSelector
//   matchLabels:
//     grp=blue
// egress:
//   toEndpoints:
//     matchLabels:
//       app=bar
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1],
//           IdentitySelector{
//             Selector: {"app=bar"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1],
//     }
//   }
// }
//
// IdentityPolicy: { // secid=20
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1],
//           IdentitySelector{
//             Selector: {"app=bar"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1],
//     }
//   }
// }
//
// Mutation-2 : Add the following rule UUID-2
// endpointSelector
//   matchLabels:
//     app=foo
// egress:
//   toEndpoints:
//     matchLabels:
//       app=bar
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1, UUID=2],
//           IdentitySelector{ // same *IdentitySelector as in secid=20
//             Selector: {"app=bar"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1, UUID-2],
//     }
//   }
// }
//
// IdentityPolicy: { // secid=20
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1],
//           IdentitySelector{ // same *IdentitySelector as in secid=10
//             Selector: {"app=bar"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1],
//     }
//   }
// }
//
// Mutation-3 : Add the following rule UUID-3
// endpointSelector
//   matchLabels:
//     app=foo
// egress:
//   toEndpoints:
//     matchLabels:
//       {}
//   toPorts:
//   - port: 80
//     protocol: tcp
//     rules:
//       http:
//         - method: GET
//           path: /public
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1, UUID=2],
//           IdentitySelector{ // same *IdentitySelector as in secid=20
//             Selector: {"app=bar"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1],
//     },
//     80: IdentityPortSelector{
//       Port: 80,
//       Protocol: tcp,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-3],
//           IdentitySelector{
//             Selector: {},
//           },
//           L7: L7Policy {
//             http: {
//               ContributingRules: [UUID-3],
//               method: GET,
//               path: /public,
//           }
//          }
//         },
//       ]
//       ContributingRules: [UUID-3],
//     }
//   }
// }
//
// IdentityPolicy: { // secid=20
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1],
//           IdentitySelector{ // same *IdentitySelector as in secid=10
//             Selector: {"app=bar"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1],
//     }
//   }
// }
//
//
// Mutation-4, UUID-4
// endpointSelector
//   matchLabels:
//     app=foo
// egress:
//   toRequires:
//     matchLabels:
//       grp=red
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     0: IdentityPortSelector{
//       Port: 0,
//       Protocol: any,
//       AllowedIdentities: [
//         AllowedIdentity{
//           BaseSelector: {"app=bar"},
//           Requirements: [{
//             Selector: {"grp-red"},
//             ContributingRules: [UUID-4],
//           }],
//           ContributingRules: [UUID-1, UUID=2],
//           IdentitySelector{ // same *IdentitySelector as in secid=20
//             Selector: {"app=bar", "grp-red"},
//           },
//         },
//       ]
//       ContributingRules: [UUID-1],
//     },
//     80: IdentityPortSelector{
//       Port: 80,
//       Protocol: tcp,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-3],
//           BaseSelector: {},
//           Requirements: [{
//             Selector: {"grp-red"},
//             ContributingRules: [UUID-4],
//           }],
//           IdentitySelector{
//             Selector: {"grp-red"},
//           },
//           L7: L7Policy {
//             http: {
//               ContributingRules: [UUID-3],
//               method: GET,
//               path: /public,
//           }
//          }
//         },
//       ]
//       ContributingRules: [UUID-3],
//     }
//   }
// }
//
//
// Walk through:
// Map to identities
//
// IdentitySelectors:
// 1: Selector: {"app=bar"}
// 2: Selector: {}
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: []
// - Selector: {}, Cached: []
//
// Identity Mutation 1: grp=blue,app=foo secid=10 appears
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: []
// - Selector: {}, Cached: [10]
//
// Result:
//  secid=10, port 80, *AllowedIdentity: identity 10 added
//
// Next steps:
//  secid=10 -> endpoint 100
//  Push [port 80, identity 10] to BPF map
//
// Identity Mutation 2: grp=blue,app=bar secid=20 appears
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: [20]
// - Selector: {}, Cached: [10, 20]
//
// Identity Mutation 3: grp=blue,app=foo secid=10 disappears
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: [20]
// - Selector: {}, Cached: [20]
//
// Result:
//   secid=10, port 80, *AllowedIdentity, identity 10 removed
//
// Next steps:
//  secid=10 -> endpoint 100
//  Remove [port 80, identity 10] from BPF map
//
// Identity Mutation 4: grp=blue,app=baz secid=30 appears
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: [20]
// - Selector: {}, Cached: [20, 30]
//
// Identity Mutation 5: reserved:world secid=2 appears
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: [20]
// - Selector: {}, Cached: [20, 30, 2]
//
// Identity Mutation 6: reserved:host secid=1 appears
//
// IdentitySelectors:
// - Selector: {"app=bar"}, Cached: [20]
// - Selector: {}, Cached: [20, 30, 2, 1]
//
//
// -----------------------------------------------------------------------------------------------
// ALTERNATIVE: L4 embedded in identity
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     AllowedIdentity{
//       ContributingRules: [UUID-1, UUID=2],
//       IdentitySelector{ // same *IdentitySelector as in secid=20
//         Selector: {"app=bar"},
//       },
//       Ports: [{
//         ContributingRules: [UUID-1, UUID-2],
//         Port: 0,
//       }]
//     },
//     AllowedIdentity{
//       ContributingRules: [UUID-3],
//       IdentitySelector{
//         Selector: {},
//       },
//       Ports: [{
//         Port: 80,
//         ContributingRules: [UUID-3],
//         L7: L7Policy {
//           http: {
//             ContributingRules: [UUID-3],
//             method: GET,
//             path: /public,
//           }
//         }
//       }]
//     }
//   }
// }
//
// Identity Mutation 1: grp=blue,app=bar secid=20 appears
//
// - Selector: {"app=bar"}, Cached: [20], Referals: [port 0, L7 wildcard]
// - Selector: {}, Cached: [20], Referals: [port 80, GET /public]
//
// secid=10 -> endpoint id 100
//
// endpoint id 100 (keep in memory)
//   push port 8080, to secid=20, GET /bar
//   push port 80, to secid=20, GET /public
//   push port 0, to secid=20, L7 wildcard
// --> merge
//   push port 8080, to secid=20, L7 wildcard
//   push port 80, to secid=20, L7 wildcard
//   push port 0, to secid=20, L7 wildcard
// --> push to BPF
//
// Rule Mutation: Remove UUID-1 & UUID-2
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     80: IdentityPortSelector{
//       Port: 80,
//       Protocol: tcp,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-3],
//           IdentitySelector{
//             Selector: {},
//           },
//           L7: L7Policy {
//             http: {
//               ContributingRules: [UUID-3],
//               method: GET,
//               path: /public,
//           }
//          }
//         },
//       ]
//       ContributingRules: [UUID-3],
//     }
//   }
// }
//
// secid=10 has removed port 0 IdentitySelector {"app=bar"}
//
// - Selector: {"app=bar"}, Cached: [20], Referals: [port 0, L7 wildcard]
//
// -> delete port 0, to secid=20, L7 wildcard
//
// endpoint id 100 (keep in memory)
//   push port 8080, to secid=20, GET /bar
//   push port 80, to secid=20, GET /public
//   push port 0, to secid=20, L7 wildcard <-- remove
// --> re-merge
//   push port 8080, to secid=20, GET /bar
//   push port 80, to secid=20, GET /public
// --> push to BPF
//
// FQDN Case Study
//
// Mutation-1, UUID1
// endpointSelector
//   matchLabels:
//     app=foo
// egress:
//   toFQDNs
//     - isovalent.com
//   toPorts:
//   - port: 80
//     protocol: tcp
//
// IdentityPolicy: { // secid=10
//   Egress: {
//     80: IdentityPortSelector{
//       Port: 80,
//       Protocol: tcp,
//       AllowedIdentities: [
//         AllowedIdentity{
//           ContributingRules: [UUID-1],
//           BaseSelector: "fqdn:isovalent.com",
//         }
//       ]
//       ContributingRules: [UUID-1],
//     }
//   }
// }
//
// FQDNSelector{
//   Selector: "fqdn:isovalent.com",
// }
//
// DNS Proxy Add Mutation: Add isovalent.com=1.1.1.1
//
// FQDNSelector{
//   Selector: "fqdn:isovalent.com",
//   ["cidr:1.1.1.1"]
// }
//
// DNS Proxy Add Mutation: Add isovalent.com=1.1.1.2
//
// FQDNSelector{
//   Selector: "fqdn:isovalent.com",
//   ["cidr:1.1.1.1", "cidr:1.1.1.2"]
// }
