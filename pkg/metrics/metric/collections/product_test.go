// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package collections

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIteratorProduct(t *testing.T) {
	assert := assert.New(t)
	p := CartesianProduct(
		[]string{"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "NetworkPolicyName"},
		[]string{"update", "delete"},
		[]string{"true", "false"},
		[]string{"0", "1"},
	)
	assert.Len(p, 24, "Should be 3 * 2 * 2 * 2 = 24 permutations")
	vs := map[string]any{}
	for _, v := range p {
		vs[fmt.Sprintf("%v", v)] = v
	}
	assert.Len(vs, 24, "Elements should be unique")
}

func TestIteratorProductElements(t *testing.T) {
	assert := assert.New(t)
	p := CartesianProduct(
		[]string{"true", "false"},
		[]string{"0", "1"},
		[]string{"foo"},
	)
	assert.Equal(4, len(p), "Should be 2 * 2 * 1 = 4 permutations")
	assert.Equal(len(p[0]), 3)
	vs := map[string]any{}
	for _, v := range p {
		vs[fmt.Sprintf("%v", v)] = v
	}
	assert.Contains(vs, "[true 0 foo]")
	assert.Contains(vs, "[true 1 foo]")
	assert.Contains(vs, "[false 0 foo]")
	assert.Contains(vs, "[false 1 foo]")
}

func TestIteratorProductEmpty(t *testing.T) {
	assert := assert.New(t)
	p := CartesianProduct(
		[]string{"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "NetworkPolicyName"},
		[]string{},
	)
	assert.Empty(p)

	p = CartesianProduct[string]()
	assert.Empty(p)

	assert.Empty(CartesianProduct([]string{}, []string{}, []string{}))
	assert.Empty(0, CartesianProduct[int]())
	assert.Len(CartesianProduct([]string{""}, []string{""}, []string{""}), 1)
	CartesianProduct[interface{}](nil, nil) // Test some weird cases.
}
