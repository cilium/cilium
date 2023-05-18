// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"testing"

	check "github.com/cilium/checkmate"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type APISuite struct{}

var _ = check.Suite(&APISuite{})

type pluginTest struct{}

func (p *pluginTest) Add(ctx context.Context, pluginContext PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	return nil, nil
}

func (p *pluginTest) Delete(ctx context.Context, pluginContext PluginContext, delClient *lib.DeletionFallbackClient) (err error) {
	return nil
}

func (p *pluginTest) Check(ctx context.Context, pluginContext PluginContext, cli *client.Client) error {
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
