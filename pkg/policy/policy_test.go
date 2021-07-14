// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

// +build !privileged_tests

package policy

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PolicyTestSuite struct{}

var _ = Suite(&PolicyTestSuite{})
