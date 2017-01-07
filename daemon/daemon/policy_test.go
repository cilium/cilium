//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"os"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
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

func (ds *DaemonSuite) TestFindNode(c *C) {
	var nullPtr *policy.Node

	pn := policy.Node{
		Name: "io.cilium",
		Children: map[string]*policy.Node{
			"foo": {},
			"bar": {},
		},
	}

	err := ds.d.PolicyAdd("io.cilium", &pn)
	c.Assert(err, Equals, nil)

	n, p, err := ds.d.findNode("io.cilium")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)
	c.Assert(p, Equals, nullPtr)

	n, p, err = ds.d.findNode("io.cilium.foo")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)
	c.Assert(p, Not(Equals), nil)

	n, p, err = ds.d.findNode("io.cilium.baz")
	c.Assert(err, Not(Equals), nil)
	c.Assert(n, Equals, nullPtr)
	c.Assert(p, Equals, nullPtr)

	n, p, err = ds.d.findNode("")
	c.Assert(err, Not(Equals), nil)
	c.Assert(n, Equals, nullPtr)
	c.Assert(p, Equals, nullPtr)

	n, p, err = ds.d.findNode("io.cilium..foo")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nullPtr)
	c.Assert(p, Not(Equals), nullPtr)

	err = ds.d.PolicyDelete("io.cilium", "")
	c.Assert(err, Equals, nil)
}

func (ds *DaemonSuite) TestPolicyGet(c *C) {
	pn := policy.Node{
		Name: "io.cilium",
		Children: map[string]*policy.Node{
			"foo": {
				Name: "magic",
			},
		},
	}

	err := ds.d.PolicyAdd("io.cilium", &pn)
	c.Assert(err, Equals, nil)

	n, err := ds.d.PolicyGet("io.cilium.foo")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)

	err = ds.d.PolicyDelete("io.cilium.foo", "")
	c.Assert(err, Equals, nil)
}

func (ds *DaemonSuite) TestUpdateConsumerMap(c *C) {
	lblProd := labels.NewLabel("io.cilium.Prod", "", common.CiliumLabelSource)
	lblQA := labels.NewLabel("io.cilium.QA", "", common.CiliumLabelSource)
	lblFoo := labels.NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblJoe := labels.NewLabel("io.cilium.user", "joe", common.CiliumLabelSource)
	lblPete := labels.NewLabel("io.cilium.user", "pete", common.CiliumLabelSource)

	rootNode := policy.Node{
		Name: common.GlobalLabelPrefix,
		Rules: []policy.PolicyRule{
			&policy.PolicyRuleConsumers{
				Coverage: []labels.Label{*lblBar},
				Allow: []policy.AllowRule{
					// always-allow: user=joe
					{Action: policy.ALWAYS_ACCEPT, Label: *lblJoe},
					// allow:  user=pete
					{Action: policy.ACCEPT, Label: *lblPete},
				},
			},
			&policy.PolicyRuleRequires{ // coverage qa, requires qa
				Coverage: []labels.Label{*lblQA},
				Requires: []labels.Label{*lblQA},
			},
			&policy.PolicyRuleRequires{ // coverage prod, requires: prod
				Coverage: []labels.Label{*lblProd},
				Requires: []labels.Label{*lblProd},
			},
		},
		Children: map[string]*policy.Node{
			"foo": {},
			"bar": {
				Rules: []policy.PolicyRule{
					&policy.PolicyRuleConsumers{
						Allow: []policy.AllowRule{
							{ // allow: foo
								Action: policy.ACCEPT,
								Label:  *lblFoo,
							},
							{Action: policy.DENY, Label: *lblJoe},
							{Action: policy.DENY, Label: *lblPete},
						},
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)

	err := ds.d.PolicyAdd("io.cilium", &rootNode)
	c.Assert(err, Equals, nil)

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.PutLabels(qaBarLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := ds.d.PutLabels(prodBarLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.PutLabels(qaFooLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := ds.d.PutLabels(prodFooLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := ds.d.PutLabels(prodFooJoeLbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)

	e := endpoint.Endpoint{
		ID:      1,
		IfName:  "dummy1",
		IPv6:    IPv6Addr,
		IPv4:    IPv4Addr,
		LXCMAC:  HardAddr,
		NodeMAC: HardAddr,
	}
	e.Opts = option.NewBoolOptions(&DaemonOptionLibrary)
	e.Opts.SetIfUnset(endpoint.OptionLearnTraffic, false)
	err = os.Mkdir("1", 755)
	c.Assert(err, IsNil)
	defer func() {
		err = os.RemoveAll("1/geneve_opts.cfg")
		err = os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		err = os.RemoveAll("1")
		err = os.RemoveAll("1_backup")
	}()
	e.SetSecLabel(qaBarSecLblsCtx)
	err = ds.d.regenerateEndpoint(&e)
	c.Assert(err, Equals, nil)
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
	}
	e.Opts = option.NewBoolOptions(&DaemonOptionLibrary)
	e.Opts.SetIfUnset(endpoint.OptionLearnTraffic, false)
	e.SetSecLabel(prodBarSecLblsCtx)
	err = ds.d.regenerateEndpoint(&e)
	c.Assert(err, Equals, nil)
	c.Assert(e.Allows(0), Equals, false)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooJoeSecLblsCtx.ID), Equals, true)

	err = ds.d.PolicyDelete("io.cilium", "")
	c.Assert(err, Equals, nil)
}
