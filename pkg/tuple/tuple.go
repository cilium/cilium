// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tuple

import (
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
	TUPLE_F_SERVICE = 4
)

// TupleKey is the interface describing keys to the conntrack and NAT maps.
type TupleKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() TupleKey

	// ToHost converts fields to host byte order.
	ToHost() TupleKey

	// Dumps contents of key to sb. Returns true if successful.
	Dump(sb *strings.Builder, reverse bool) bool

	// Returns flags containing the direction of the tuple key.
	GetFlags() uint8
}
