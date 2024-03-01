// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_settingsComputeDeltas(t *testing.T) {
	uu := map[string]struct {
		m1, m2 map[string]string
		e      []string
	}{
		"empty": {},
		"no-key": {
			m1: map[string]string{
				"blee": "bozo",
			},
			e: []string{`No entry found for key: [test::blee]`},
		},
		"mismatch": {
			m1: map[string]string{
				"k1": "v1",
			},
			m2: map[string]string{
				"k1": "v1_1",
			},
			e: []string{
				`Mismatch for key [test::k1]: expecting "v1" but got "v1_1"`,
			},
		},
		"full-monty": {
			m1: map[string]string{
				"k1": "v1",
				"k2": "v2_1",
				"k3": "v3",
			},
			m2: map[string]string{
				"k1": "v1_1",
				"k2": "v2",
			},
			e: []string{
				`Mismatch for key [test::k1]: expecting "v1" but got "v1_1"`,
				`Mismatch for key [test::k2]: expecting "v2_1" but got "v2"`,
				`No entry found for key: [test::k3]`,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, newSourceSettings("test", u.m1).computeDeltas(u.m2))
		})
	}
}

func Test_settingsComputeCheckSum(t *testing.T) {
	uu := map[string]struct {
		m map[string]string
		e string
	}{
		"empty": {
			e: "d41d8cd98f00b204e9800998ecf8427e",
		},
		"single": {
			m: map[string]string{
				"blee": "bozo",
			},
			e: "631965565930ace7df990f739794e49f",
		},
		"multi": {
			m: map[string]string{
				"k1": "v1",
				"k2": "v2_1",
				"k3": "v3",
			},
			e: "f5095f362f682d1721080ddc7d0f8a21",
		},
		"order": {
			m: map[string]string{
				"k2": "v2_1",
				"k3": "v3",
				"k1": "v1",
			},
			e: "f5095f362f682d1721080ddc7d0f8a21",
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, newSourceSettings("test", u.m).computeCheckSum())
		})
	}
}
