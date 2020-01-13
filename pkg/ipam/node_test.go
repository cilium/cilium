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

package ipam

import (
	"gopkg.in/check.v1"
)

type testNeededDef struct {
	available   int
	used        int
	preallocate int
	minallocate int
	result      int
}

type testExcessDef struct {
	available         int
	used              int
	preallocate       int
	minallocate       int
	maxabovewatermark int
	result            int
}

var neededDef = []testNeededDef{
	{0, 0, 0, 16, 16},
	{0, 0, 8, 16, 16},
	{0, 0, 16, 8, 16},
	{0, 0, 16, 0, 16},
	{8, 0, 0, 16, 8},
	{8, 4, 8, 0, 4},
	{8, 4, 8, 8, 4},
}

var excessDef = []testExcessDef{
	{0, 0, 0, 16, 0, 0},
	{15, 0, 8, 16, 8, 0},
	{17, 0, 8, 16, 0, 9}, // 17 used, 8 pre-allocate, 16 min-allocate => 1 excess
	{20, 0, 8, 16, 4, 0}, // 20 used, 8 pre-allocate, 16 min-allocate, 4 max-above-watermark => 0 excess
	{21, 0, 8, 0, 4, 9},  // 21 used, 8 pre-allocate, 4 max-above-watermark => 9 excess
	{20, 0, 8, 20, 8, 0},
	{16, 1, 8, 16, 8, 0},
	{20, 4, 8, 17, 8, 0},
	{20, 4, 8, 0, 0, 8},
	{20, 4, 8, 0, 8, 0},
}

func (e *IPAMSuite) TestCalculateNeededIPs(c *check.C) {
	for _, d := range neededDef {
		result := calculateNeededIPs(d.available, d.used, d.preallocate, d.minallocate)
		c.Assert(result, check.Equals, d.result)
	}
}

func (e *IPAMSuite) TestCalculateExcessIPs(c *check.C) {
	for _, d := range excessDef {
		result := calculateExcessIPs(d.available, d.used, d.preallocate, d.minallocate, d.maxabovewatermark)
		c.Assert(result, check.Equals, d.result)
	}
}
