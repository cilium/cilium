// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build race

package rate

import "testing"

func TestStressRateLimiter(t *testing.T) {
	testStressRateLimiter(t, 72)
}
