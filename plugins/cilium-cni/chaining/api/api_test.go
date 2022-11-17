// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"testing"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
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

func (p *pluginTest) Check(ctx context.Context, pluginContext PluginContext) error {
	return nil
}

func (a *APISuite) TestRegistration(c *check.C) {
	err := Register("foo", &pluginTest{})
	c.Assert(err, check.IsNil)

	err = Register("foo", &pluginTest{})
	c.Assert(err, check.Not(check.IsNil))

	err = Register(DefaultConfigName, &pluginTest{})
	c.Assert(err, check.Not(check.IsNil))
}

func (a *APISuite) TestNonChaining(c *check.C) {
	c.Assert(Lookup("cilium"), check.IsNil)
}
