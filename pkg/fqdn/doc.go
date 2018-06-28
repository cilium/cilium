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

// Package fqdn handles DNS based policy enforcment. This is expressed via
// ToFQDN rules and implements a DNS polling scheme with DNS lookups
// originating from the Cilium agent.
//
// Note: We add a ToFQDN-UUID label to rules when we process a ToFQDN section.
// This has the source cilium-generated and should not be modified outside
// pkg/fqdn
//
// The poller will update imported policy rules that contain ToFQDN sections
// with matching ToCIDRSet sections (in the same egress rule, thus inheriting
// the same L4/L7 policy). Each CIDR is a fully qualified IP (i.e. a /32 or
// /128) and each IP returned in the DNS lookup creates a corresponding CIDR.
// The package relies on the internal policy logic to return early/trigger no
// regenerations if the policy is not actually different (e.g. a more
// broad/permissive rule already applies to an endpoint so any IP changes are
// irrelevant).
package fqdn
