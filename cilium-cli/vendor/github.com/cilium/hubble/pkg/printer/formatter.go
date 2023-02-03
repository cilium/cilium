// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

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
