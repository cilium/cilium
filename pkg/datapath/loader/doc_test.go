// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package loader

import (
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// Hook up gocheck into the "go test" runner.
type LoaderTestSuite struct{}

var _ = Suite(&LoaderTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LoaderTestSuite) SetUpTest(c *C) {
	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	node.InitDefaultPrefix("")
	node.SetInternalIPv4Router(templateIPv4)
	node.SetIPv4Loopback(templateIPv4)
}
