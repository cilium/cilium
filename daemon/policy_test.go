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

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

var (
	HardAddr    = mac.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
)

func (ds *DaemonSuite) TestUpdateConsumerMap(c *C) {
	lblProd := labels.ParseLabel("Prod")
	lblQA := labels.ParseLabel("QA")
	lblFoo := labels.ParseLabel("foo")
	lblBar := labels.ParseLabel("bar")
	lblJoe := labels.ParseLabel("user=joe")
	lblPete := labels.ParseLabel("user=pete")

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblJoe),
						api.NewESFromLabels(lblPete),
						api.NewESFromLabels(lblFoo),
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblQA),
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblProd),
					},
				},
			},
		},
	}

	_, err3 := ds.d.PolicyAdd(rules, nil)
	c.Assert(err3, Equals, nil)

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := policy.AllocateIdentity(qaBarLbls)
	c.Assert(err, Equals, nil)

	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := policy.AllocateIdentity(prodBarLbls)
	c.Assert(err, Equals, nil)

	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := policy.AllocateIdentity(qaFooLbls)
	c.Assert(err, Equals, nil)

	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := policy.AllocateIdentity(prodFooLbls)
	c.Assert(err, Equals, nil)

	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := policy.AllocateIdentity(prodFooJoeLbls)
	c.Assert(err, Equals, nil)

	e := endpoint.NewEndpointWithState(1, endpoint.StateWaitingForIdentity)
	e.IfName = "dummy1"
	e.IPv6 = IPv6Addr
	e.IPv4 = IPv4Addr
	e.LXCMAC = HardAddr
	e.NodeMAC = HardAddr

	err2 := os.Mkdir("1", 755)
	c.Assert(err2, IsNil)
	defer func() {
		os.RemoveAll("1/geneve_opts.cfg")
		os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		os.RemoveAll("1")
		os.RemoveAll("1_backup")
	}()
	e.SetIdentity(ds.d, qaBarSecLblsCtx)
	e.Mutex.Lock()
	ready := e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Mutex.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(ds.d, "test")
	c.Assert(buildSuccess, Equals, true)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, false)

	e = endpoint.NewEndpointWithState(1, endpoint.StateWaitingForIdentity)
	e.IfName = "dummy1"
	e.IPv6 = IPv6Addr
	e.IPv4 = IPv4Addr
	e.LXCMAC = HardAddr
	e.NodeMAC = HardAddr
	e.SetIdentity(ds.d, prodBarSecLblsCtx)
	e.Mutex.Lock()
	ready = e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Mutex.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess = <-e.Regenerate(ds.d, "test")
	c.Assert(buildSuccess, Equals, true)
	c.Assert(e.Allows(0), Equals, false)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooJoeSecLblsCtx.ID), Equals, true)
}

func (ds *DaemonSuite) TestReplacePolicy(c *C) {
	lblBar := labels.ParseLabel("bar")
	lbls := labels.ParseLabelArray("foo", "bar")
	rules := api.Rules{
		{
			Labels:           lbls,
			EndpointSelector: api.NewESFromLabels(lblBar),
		},
		{
			Labels:           lbls,
			EndpointSelector: api.NewESFromLabels(lblBar),
		},
	}

	_, err := ds.d.PolicyAdd(rules, nil)
	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()
	_, err = ds.d.PolicyAdd(rules, &AddOptions{Replace: true})
	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()
}
