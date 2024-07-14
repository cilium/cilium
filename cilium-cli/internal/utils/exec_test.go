// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type failIfCalled struct {
	t *testing.T
}

func (f *failIfCalled) Log(_ string, _ ...interface{}) {
	f.t.Error("log method should not be called")
}

type countIfCalled struct {
	count int
}

func (c *countIfCalled) Log(_ string, _ ...interface{}) {
	c.count++
}

func TestExec(t *testing.T) {
	_, err := Exec(&failIfCalled{t}, "true")
	assert.NoError(t, err)

	cl := &countIfCalled{0}
	_, err = Exec(cl, "false")
	assert.Error(t, err)
	assert.Equal(t, 1, cl.count)

	cl.count = 0
	_, err = Exec(cl, "sh", "-c", "'echo foo; exit 1'")
	assert.Error(t, err)
	assert.Equal(t, 2, cl.count)
}
