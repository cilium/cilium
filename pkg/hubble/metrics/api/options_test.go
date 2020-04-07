// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

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
