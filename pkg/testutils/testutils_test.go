// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"

	. "github.com/cilium/checkmate"
)

func Test(t *testing.T) {
	TestingT(t)
}

type TestUtilsSuite struct{}

var _ = Suite(&TestUtilsSuite{})
