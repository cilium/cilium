// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

func TestMapValueGroup(t *testing.T) {
	type t1 struct{}
	type t2 struct{}
	type t3 struct{}

	h := hive.New(
		cell.Provide(func(in MapGroup) bool {
			assert.Len(t, in.Group, 3)
			assert.Contains(t, in.Group, t1{})
			assert.Contains(t, in.Group, t2{})
			assert.Contains(t, in.Group, hive.None[t3]())

			return true
		}),
		cell.Provide(func() MapOut[t1] {
			return NewMapOut(t1{})
		}),
		cell.Provide(func() MapOut[t2] {
			return NewMapOut(t2{})
		}),
		cell.Provide(func() MaybeMapOut[t3] {
			return NoneMap[t3]()
		}),

		cell.Invoke(func(b bool) {}),
	)

	l, ctx := hivetest.Logger(t), t.Context()
	assert.NoError(t, h.Start(l, ctx))
	assert.NoError(t, h.Stop(l, ctx))
}
