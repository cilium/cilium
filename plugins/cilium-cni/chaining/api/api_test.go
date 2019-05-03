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

package api

import (
	"context"
	"testing"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type APISuite struct{}

var _ = check.Suite(&APISuite{})

type pluginTest struct{}

func (p *pluginTest) Add(ctx context.Context, pluginContext PluginContext) (res *cniTypesVer.Result, err error) {
	return nil, nil
}

func (p *pluginTest) ImplementsAdd() bool {
	return true
}

func (p *pluginTest) Delete(ctx context.Context, pluginContext PluginContext) (err error) {
	return nil
}

func (p *pluginTest) ImplementsDelete() bool {
	return true
}

func (a *APISuite) TestRegistration(c *check.C) {
	err := Register("foo", &pluginTest{})
	c.Assert(err, check.IsNil)

	err = Register("foo", &pluginTest{})
	c.Assert(err, check.Not(check.IsNil))
}
