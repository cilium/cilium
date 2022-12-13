// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/tuple"

type NatKey4 struct {
	tuple.TupleKey4Global
}

type NatKey6 struct {
	tuple.TupleKey6Global
}
