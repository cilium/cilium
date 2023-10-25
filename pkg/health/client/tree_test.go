// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTreeAddNode(t *testing.T) {
	r := newRoot("fred")
	r.addNode("a")
	b := r.addBranch("b")
	b.addNode("b1")
	r.addNode("c")
	r.addNodeWithMeta("d", "blee")

	assert.Equal(t, "fred\n├── a\n├── b\n│   └── b1\n├── c\n└── d                                                       blee\n", r.String())
}

func TestTreeAddBranch(t *testing.T) {
	r := newRoot("fred")
	r.addBranch("a")
	b := r.addBranch("b")
	b1 := b.addBranch("b1")
	b1.addNode("b1_1")
	r.addBranch("c")
	r.addBranchWithMeta("d", "blee")

	assert.Equal(t, "fred\n├── a\n├── b\n│   └── b1\n│       └── b1_1\n├── c\n└── d                                                       blee\n", r.String())
}

func TestTreeFind(t *testing.T) {
	r := newRoot("fred")
	r.addBranch("a")
	b := r.addBranch("b")
	b1 := b.addBranch("b1")
	b11 := b1.addNode("b1_1")
	c := r.addNode("c")
	r.addBranchWithMeta("d", "blee")

	uu := map[string]struct {
		v string
		e *node
	}{
		"none": {
			v: "bozo",
		},
		"leaf": {
			v: "b1_1",
			e: b11,
		},
		"node": {
			v: "c",
			e: c,
		},
		"branch": {
			v: "b1",
			e: b1,
		},
	}
	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, r.find(u.v))
		})
	}
}
