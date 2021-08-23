// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package install

import (
	"strings"
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type InstallSuite struct{}

var _ = check.Suite(&InstallSuite{})

func (b *InstallSuite) TestGenerateKey(c *check.C) {
	k, err := generateRandomKey()
	c.Assert(err, check.IsNil)
	tokens := strings.Split(k, " ")
	// 3 rfc4106(gcm(aes)) 5118217c0a040d9a4cc22da05bcd677db33cb30d 128
	c.Assert(len(tokens), check.Equals, 4)
}
