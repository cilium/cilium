// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"os"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	. "gopkg.in/check.v1"
)

var (
	HardAddr    = mac.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
)

func (ds *DaemonSuite) TestUpdateConsumerMap(c *C) {
	lblProd := labels.NewLabel("root.Prod", "", common.CiliumLabelSource)
	lblQA := labels.NewLabel("root.QA", "", common.CiliumLabelSource)
	lblFoo := labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("root.bar", "", common.CiliumLabelSource)
	lblJoe := labels.NewLabel("root.user", "joe", common.CiliumLabelSource)
	lblPete := labels.NewLabel("root.user", "pete", common.CiliumLabelSource)

	rootNode := policy.Node{
		Name: "root",
		Rules: []policy.PolicyRule{
			&policy.RuleConsumers{
				Coverage: []*labels.Label{lblBar},
				Allow: []*policy.AllowRule{
					// always-allow: user=joe
					{Action: policy.ALWAYS_ACCEPT, Label: lblJoe},
					// allow:  user=pete
					{Action: policy.ACCEPT, Label: lblPete},
				},
			},
			&policy.RuleRequires{ // coverage qa, requires qa
				Coverage: []*labels.Label{lblQA},
				Requires: []*labels.Label{lblQA},
			},
			&policy.RuleRequires{ // coverage prod, requires: prod
				Coverage: []*labels.Label{lblProd},
				Requires: []*labels.Label{lblProd},
			},
		},
		Children: map[string]*policy.Node{
			"foo": {},
			"bar": {
				Rules: []policy.PolicyRule{
					&policy.RuleConsumers{
						Allow: []*policy.AllowRule{
							{ // allow: foo
								Action: policy.ACCEPT,
								Label:  lblFoo,
							},
							{Action: policy.DENY, Label: lblJoe},
							{Action: policy.DENY, Label: lblPete},
						},
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), IsNil)

	err3 := ds.d.PolicyAdd("root", &rootNode)
	c.Assert(err3, Equals, nilAPIError)

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.CreateOrUpdateIdentity(qaBarLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := ds.d.CreateOrUpdateIdentity(prodBarLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.CreateOrUpdateIdentity(qaFooLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := ds.d.CreateOrUpdateIdentity(prodFooLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := ds.d.CreateOrUpdateIdentity(prodFooJoeLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	e := endpoint.Endpoint{
		ID:      1,
		IfName:  "dummy1",
		IPv6:    IPv6Addr,
		IPv4:    IPv4Addr,
		LXCMAC:  HardAddr,
		NodeMAC: HardAddr,
		Status:  endpoint.NewEndpointStatus(),
	}
	e.Opts = option.NewBoolOptions(&options.Library)
	err2 := os.Mkdir("1", 755)
	c.Assert(err2, IsNil)
	defer func() {
		err2 = os.RemoveAll("1/geneve_opts.cfg")
		err2 = os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		err2 = os.RemoveAll("1")
		err2 = os.RemoveAll("1_backup")
	}()
	e.SetIdentity(ds.d, qaBarSecLblsCtx)
	buildSuccess := <-e.Regenerate(ds.d)
	c.Assert(buildSuccess, Equals, true)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodFooJoeSecLblsCtx.ID), Equals, true)

	e = endpoint.Endpoint{
		ID:      1,
		IfName:  "dummy1",
		IPv6:    IPv6Addr,
		IPv4:    IPv4Addr,
		LXCMAC:  HardAddr,
		NodeMAC: HardAddr,
		Status:  endpoint.NewEndpointStatus(),
	}
	e.Opts = option.NewBoolOptions(&options.Library)
	e.SetIdentity(ds.d, prodBarSecLblsCtx)
	buildSuccess = <-e.Regenerate(ds.d)
	c.Assert(buildSuccess, Equals, true)
	c.Assert(e.Allows(0), Equals, false)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooJoeSecLblsCtx.ID), Equals, true)

	err = ds.d.PolicyDelete("root", "")
	c.Assert(err, IsNil)
}
