// Copyright 2021 Authors of Hubble
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

package printer

import (
	"math"
	"strconv"
	"time"
)

// uint64Grouping formats n by grouping digits by 3, separated by a comma
// (e.g. 1000000 is formatted as 1,000,000).
func uint64Grouping(n uint64) string {
	in := strconv.FormatUint(n, 10)
	if n < 1000 {
		return in
	}

	s := make([]byte, len(in)+((len(in)-1)/3))
	for i, j, k := len(in)-1, len(s)-1, 0; ; i, j = i-1, j-1 {
		s[j] = in[i]
		if i == 0 {
			return string(s)
		}
		if k++; k == 3 {
			j, k = j-1, 0
			s[j] = ','
		}
	}
}

// formatDurationNS formats a duration expressed in nanosecond to a human
// readable duration. For example, 100_000_000_000 is formatted as 1m40s.
func formatDurationNS(ns uint64) string {
	if ns > math.MaxInt64 {
		// duration doesn't fit in a time.Duration (int64)
		return strconv.FormatUint(ns, 10) + "ns"
	}
	return time.Duration(ns).String()
}
