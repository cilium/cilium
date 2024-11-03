// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "strconv"

// AuthType enumerates the supported authentication types in api.
// Numerically higher type takes precedence in case of conflicting auth types.
type AuthType uint8

// AuthTypes is a set of AuthTypes, usually nil if empty
type AuthTypes map[AuthType]struct{}

const (
	// AuthTypeDisabled means no authentication required
	AuthTypeDisabled AuthType = iota
	// AuthTypeSpire is a mutual auth type that uses SPIFFE identities with a SPIRE server
	AuthTypeSpire
	// AuthTypeAlwaysFail is a simple auth type that always denies the request
	AuthTypeAlwaysFail
)

// AuthRequirement is a combination of an AuthType with an 'explicit' flag on the highest bit This
// is defined in order to keep MapStateEntry smaller and to simplify code wiring this to the bpf
// datapath.
//
// NOTE: This type is part of the bpf policy API.
//
// This type reflects the layout of the 'auth_type' field in the bpf policy map and is used in
// pkg/maps/policymap. This layout must not be changed!
type AuthRequirement AuthType

const (
	NoAuthRequirement  AuthRequirement = 0
	AuthTypeIsExplicit AuthRequirement = 1 << 7
)

func (a AuthRequirement) IsExplicit() bool {
	return a&AuthTypeIsExplicit != 0
}

// asDerived returns the auth requirement with the 'explicit' flag cleared.
func (a AuthRequirement) AsDerived() AuthRequirement {
	return a & ^AuthTypeIsExplicit
}

func (a AuthRequirement) AuthType() AuthType {
	return AuthType(a.AsDerived())
}

func (a AuthType) AsDerivedRequirement() AuthRequirement {
	return AuthRequirement(a)
}

func (a AuthType) AsExplicitRequirement() AuthRequirement {
	return AuthRequirement(a) | AuthTypeIsExplicit
}

// Uint8 returns AuthType as a uint8
func (a AuthType) Uint8() uint8 {
	return uint8(a)
}

// String returns AuthType as a string.
// This must return the strings accepted for api.AuthType
func (a AuthType) String() string {
	switch a {
	case AuthTypeDisabled:
		return "disabled"
	case AuthTypeSpire:
		return "spire"
	case AuthTypeAlwaysFail:
		return "test-always-fail"
	}
	return "Unknown-auth-type-" + strconv.FormatUint(uint64(a.Uint8()), 10)
}
