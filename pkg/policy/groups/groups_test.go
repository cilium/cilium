// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

// +build !privileged_tests

package groups

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type GroupsTestSuite struct{}

var _ = Suite(&GroupsTestSuite{})
