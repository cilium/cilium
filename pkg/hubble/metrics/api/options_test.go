// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOptions(t *testing.T) {
	opts := ParseOptions("")
	assert.EqualValues(t, len(opts), 0)

	opts = ParseOptions("foo")
	assert.EqualValues(t, len(opts), 1)
	assert.EqualValues(t, opts["foo"], "")

	opts = ParseOptions("foo;bar")
	assert.EqualValues(t, len(opts), 2)
	assert.EqualValues(t, opts["foo"], "")
	assert.EqualValues(t, opts["bar"], "")

	opts = ParseOptions("foo;bar=x")
	assert.EqualValues(t, len(opts), 2)
	assert.EqualValues(t, opts["foo"], "")
	assert.EqualValues(t, opts["bar"], "x")
}
