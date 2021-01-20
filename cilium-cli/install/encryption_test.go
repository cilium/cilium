// Copyright 2020-2021 Authors of Cilium
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
