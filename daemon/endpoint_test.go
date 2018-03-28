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

package main

import (
	"github.com/cilium/cilium/api/v1/models"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func getEPTemplate(c *C) *models.EndpointChangeRequest {
	ip4, ip6, err := ipam.AllocateNext("")
	c.Assert(err, Equals, nil)
	c.Assert(ip4, Not(IsNil))
	c.Assert(ip6, Not(IsNil))

	id := int64(addressing.CiliumIPv6(ip6).EndpointID())
	return &models.EndpointChangeRequest{
		ID:            id,
		ContainerID:   endpoint.NewCiliumID(id),
		ContainerName: "foo",
		State:         models.EndpointStateWaitingForIdentity,
		Addressing: &models.EndpointAddressing{
			IPV6: ip6.String(),
			IPV4: ip4.String(),
		},
	}
}

func (ds *DaemonSuite) TestEndpointAdd(c *C) {
	epTemplate := getEPTemplate(c)
	lbls := []string{"reserved:world"}
	code, err := ds.d.createEndpoint(epTemplate, "1", lbls)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	lbls = []string{"reserved:foo"}
	code, err = ds.d.createEndpoint(epTemplate, "1", lbls)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)
}

func (ds *DaemonSuite) TestUpdateSecLabels(c *C) {
	lbls := labels.NewLabelsFromModel([]string{"reserved:world"})
	code, err := ds.d.updateEndpointLabelsFromAPI("1", lbls, nil)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PatchEndpointIDLabelsUpdateFailedCode)
}
