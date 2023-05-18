// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

func (ds *FQDNTestSuite) SetUpSuite(c *C) {
	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
}

type FQDNTestSuite struct{}

var _ = Suite(&FQDNTestSuite{})
