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

package identity

import "github.com/cilium/cilium/pkg/labels"

var (
	// ReservedIdentityCache that maps all reserved identities from their
	// numeric identity to their corresponding identity.
	ReservedIdentityCache = map[NumericIdentity]*Identity{}
)

// AddReservedIdentity adds the reserved numeric identity with the respective
// label into the map of reserved identity cache.
func AddReservedIdentity(ni NumericIdentity, lbl string) {
	identity := NewIdentity(ni, labels.Labels{lbl: labels.NewLabel(lbl, "", labels.LabelSourceReserved)})
	// Pre-calculate the SHA256 hash.
	identity.GetLabelsSHA256()
	ReservedIdentityCache[ni] = identity
}

// LookupReservedIdentity looks up a reserved identity by its NumericIdentity
// and returns it if found. Returns nil if not found.
func LookupReservedIdentity(ni NumericIdentity) *Identity {
	return ReservedIdentityCache[ni]
}

func init() {
	IterateReservedIdentities(func(lbl string, ni NumericIdentity) {
		identity := NewIdentity(ni, labels.Labels{lbl: labels.NewLabel(lbl, "", labels.LabelSourceReserved)})
		// Pre-calculate the SHA256 hash.
		identity.GetLabelsSHA256()
		ReservedIdentityCache[ni] = identity
	})
}
