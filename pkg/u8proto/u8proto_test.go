// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package u8proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestU8Proto(t *testing.T) {
	assert := assert.New(t)
	p := TCP
	assert.Equal("TCP", p.String())
	d, err := p.MarshalText()
	assert.NoError(err)
	assert.Equal("TCP", string(d))
}
