// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"github.com/cilium/cilium/pkg/identity"
)

// reservedIdentitiesNames returns a slice of all the reserved identity
// strings.
func reservedIdentitiesNames() []string {
	identities := identity.GetAllReservedIdentities()
	names := make([]string, len(identities))
	for i, id := range identities {
		names[i] = id.String()
	}
	return names
}

// parseIdentity parse and return both numeric and reserved identities, or an
// error.
func parseIdentity(s string) (identity.NumericIdentity, error) {
	if id := identity.GetReservedID(s); id != identity.IdentityUnknown {
		return id, nil
	}
	return identity.ParseNumericIdentity(s)
}
