// Copyright 2019 Authors of Cilium
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

package main

import (
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type OperatorSuite struct{}

var _ = check.Suite(&OperatorSuite{})

func (b *OperatorSuite) TestCalculateNeededAddresses(c *check.C) {
	type testDef struct {
		available   int
		used        int
		preallocate int
		minallocate int
		result      int
	}

	def := []testDef{
		{0, 0, 0, 16, 16},
		{0, 0, 8, 16, 16},
		{0, 0, 16, 8, 16},
		{0, 0, 16, 0, 16},
		{8, 0, 0, 16, 8},
		{8, 4, 8, 0, 4},
		{8, 4, 8, 8, 4},
	}

	for _, d := range def {
		result := calculateNeededAddresses(d.available, d.used, d.preallocate, d.minallocate)
		c.Assert(result, check.Equals, d.result)
	}
}
