// Copyright 2018 Authors of Cilium
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

package main

import (
	"context"
	"net"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/checker"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	. "gopkg.in/check.v1"
)

func getEPTemplate(c *C, d *Daemon) *models.EndpointChangeRequest {
	ip4, ip6, err := d.ipam.AllocateNext("", "test")
	c.Assert(err, Equals, nil)
	c.Assert(ip4, Not(IsNil))
	c.Assert(ip6, Not(IsNil))

	return &models.EndpointChangeRequest{
		ContainerName: "foo",
		State:         models.EndpointStateWaitingForIdentity,
		Addressing: &models.AddressPair{
			IPV6: ip6.IP.String(),
			IPV4: ip4.IP.String(),
		},
	}
}

func (ds *DaemonSuite) TestEndpointAddReservedLabel(c *C) {
	epTemplate := getEPTemplate(c, ds.d)
	epTemplate.Labels = []string{"reserved:world"}
	_, code, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)
}

func (ds *DaemonSuite) TestEndpointAddInvalidLabel(c *C) {
	epTemplate := getEPTemplate(c, ds.d)
	epTemplate.Labels = []string{"reserved:foo"}
	_, code, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)
}

func (ds *DaemonSuite) TestEndpointAddNoLabels(c *C) {
	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(c, ds.d)
	_, _, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, IsNil)

	expectedLabels := labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	// Check that the endpoint has the reserved:init label.
	ep, err := ds.d.endpointManager.Lookup(endpointid.NewIPPrefixID(net.ParseIP(epTemplate.Addressing.IPV4)))
	c.Assert(err, IsNil)
	c.Assert(ep.OpLabels.IdentityLabels(), checker.DeepEquals, expectedLabels)

	// Check that the endpoint received the reserved identity for the
	// reserved:init entities.
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	var secID *identity.Identity
Loop:
	for {
		select {
		case <-timeout.C:
			break Loop
		case <-tick.C:
			ep.UnconditionalRLock()
			secID = ep.SecurityIdentity
			ep.RUnlock()
			if secID != nil {
				break Loop
			}
		}
	}
	c.Assert(secID, Not(IsNil))
	c.Assert(secID.ID, Equals, identity.ReservedIdentityInit)
}

func (ds *DaemonSuite) TestUpdateSecLabels(c *C) {
	lbls := labels.NewLabelsFromModel([]string{"reserved:world"})
	code, err := ds.d.modifyEndpointIdentityLabelsFromAPI("1", lbls, nil)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PatchEndpointIDLabelsUpdateFailedCode)
}
