// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iterator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIteratorProduct(t *testing.T) {
	assert := assert.New(t)
	a := Vec1[string]([]string{"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "NetworkPolicyName"})
	b := Vec1[string]([]string{"update", "delete"})
	c := Vec1[string]([]string{"true", "false"})
	d := Vec1[string]([]string{"0", "1"})
	p := CartesianProduct[string](a, b, c, d)
	count := 0
	p.ForEach(func(v []string) {
		count++
	})
	assert.Equal(24, count)
}
