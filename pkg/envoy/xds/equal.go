// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import "google.golang.org/protobuf/proto"

type messageVTEqualer interface {
	EqualMessageVT(proto.Message) bool
}

// ResourceEqual compares protobuf resources semantically. Generated VT
// equality avoids reflection for resource types which support it, while other
// protobufs retain proto.Equal semantics.
func ResourceEqual(left, right proto.Message) bool {
	if equaler, ok := left.(messageVTEqualer); ok {
		return equaler.EqualMessageVT(right)
	}
	if equaler, ok := right.(messageVTEqualer); ok {
		return equaler.EqualMessageVT(left)
	}
	return proto.Equal(left, right)
}
