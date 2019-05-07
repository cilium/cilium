// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package client

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type ClientTestSuite struct{}

var _ = Suite(&ClientTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (cs *ClientTestSuite) TestHint(c *C) {
	var err error
	c.Assert(Hint(err), IsNil)

	err = errors.New("foo bar")
	c.Assert(Hint(err), ErrorMatches, "foo bar")

	err = fmt.Errorf("ayy lmao")
	c.Assert(Hint(err), ErrorMatches, "ayy lmao")

	err = context.DeadlineExceeded
	c.Assert(Hint(err), ErrorMatches, "Cilium API client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	c.Assert(Hint(err), ErrorMatches, "Cilium API client timeout exceeded")
}
