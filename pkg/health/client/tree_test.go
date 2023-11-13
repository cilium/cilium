// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeMaxLevel(t *testing.T) {
	uu := map[string]struct {
		n   *node
		max int
	}{
		"empty": {},
		"single": {
			n: &node{val: "n1", meta: "m1"},
		},
		"flat": {
			n: &node{val: "n1", meta: "m1", nodes: []*node{
				{val: "n2", meta: "m2"},
				{val: "n3", meta: "m3"},
			}},
			max: 1,
		},
		"multi": {
			n: &node{val: "n1", meta: "m1", nodes: []*node{
				{val: "n1_1", meta: "m1_1", nodes: []*node{
					{val: "n1_1_1", meta: "m1_1_1", nodes: []*node{
						{val: "n1_1_1_1", meta: "m1_1_1_1"},
						{val: "n1_1_1_2", meta: "m1_1_1_2"},
					}},
				}},
				{val: "n2", meta: "m2", nodes: []*node{
					{val: "n2_1", meta: "m2_1", nodes: []*node{
						{val: "n2_1_1", meta: "m2_1_1"},
					}},
				}},
				{val: "n3", meta: "m3"},
			}},
			max: 3,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.max, computeMaxLevel(0, u.n))
		})
	}
}

func TestTreeAddNode(t *testing.T) {
	r := newRoot("fred")
	r.addNode("a")
	b := r.addBranch("b")
	b.addNode("b1")
	r.addNode("c")
	r.addNodeWithMeta("d", "blee")

	assert.Equal(t, `fred
├── a
├── b
│   └── b1
├── c
└── d                                               blee
`, r.String())
}

func TestTreeAddBranch(t *testing.T) {
	r := newRoot("fred")
	r.addBranch("a")
	b := r.addBranch("b")
	b1 := b.addBranch("b1")
	b1.addNode("b1_1")
	r.addBranch("c")
	r.addBranchWithMeta("d", "blee")

	assert.Equal(t, `fred
├── a
├── b
│   └── b1
│       └── b1_1
├── c
└── d                                                   blee
`, r.String())
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
