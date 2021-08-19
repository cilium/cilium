// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package testutils

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type TestUtilsSuite struct{}

var _ = Suite(&TestUtilsSuite{})
