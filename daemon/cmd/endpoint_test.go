// Copyright 2018-2020 Authors of Cilium
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

package cmd

import (
	"context"
	"net"
	"runtime"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/checker"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"

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
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)

	epTemplate := getEPTemplate(c, ds.d)
	epTemplate.Labels = []string{"reserved:world"}
	_, code, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)
	assertOnMetric(c, string(models.EndpointStateInvalid), 0)

	// Endpoint is created with inital label as well as disallowed
	// reserved:world label.
	epTemplate.Labels = append(epTemplate.Labels, "reserved:init")
	_, code, err = ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	c.Assert(err, ErrorMatches, "not allowed to add reserved labels:.+")
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)
	assertOnMetric(c, string(models.EndpointStateInvalid), 0)
}

func (ds *DaemonSuite) TestEndpointAddInvalidLabel(c *C) {
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)

	epTemplate := getEPTemplate(c, ds.d)
	epTemplate.Labels = []string{"reserved:foo"}
	_, code, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	// Endpoint was created with invalid data; should transition from
	// WaitingForIdentity -> Invalid.
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)
	assertOnMetric(c, string(models.EndpointStateInvalid), 0)
}

func (ds *DaemonSuite) TestEndpointAddNoLabels(c *C) {
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)

	// For this test case, we want to allow the endpoint controllers to rebuild
	// the endpoint after getting new labels.
	ds.OnQueueEndpointBuild = ds.d.QueueEndpointBuild

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(c, ds.d)
	_, _, err := ds.d.createEndpoint(context.TODO(), ds, epTemplate)
	c.Assert(err, IsNil)

	expectedLabels := labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	// Check that the endpoint has the reserved:init label.
	ep, err := ds.d.endpointManager.Lookup(endpointid.NewIPPrefixID(net.ParseIP(epTemplate.Addressing.IPV4)))
	c.Assert(err, IsNil)
	c.Assert(ep.OpLabels.IdentityLabels(), checker.DeepEquals, expectedLabels)

	secID := ep.WaitForIdentity(3 * time.Second)
	c.Assert(secID, Not(IsNil))
	c.Assert(secID.ID, Equals, identity.ReservedIdentityInit)

	// Endpoint should transition from Regenerating -> Ready after we've
	// waitied for its new identity. The presence of new labels triggers a
	// regeneration.
	assertOnMetric(c, string(models.EndpointStateRegenerating), 0)
	assertOnMetric(c, string(models.EndpointStateReady), 1)
}

func (ds *DaemonSuite) TestUpdateSecLabels(c *C) {
	lbls := labels.NewLabelsFromModel([]string{"reserved:world"})
	code, err := ds.d.modifyEndpointIdentityLabelsFromAPI("1", lbls, nil)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PatchEndpointIDLabelsUpdateFailedCode)
}

func (ds *DaemonSuite) TestUpdateLabelsFailed(c *C) {
	cancelledContext, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	cancelFunc() // Cancel immediatly to trigger the codepath to test.

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(c, ds.d)
	_, _, err := ds.d.createEndpoint(cancelledContext, ds, epTemplate)
	c.Assert(err, ErrorMatches, "request cancelled while resolving identity")

	assertOnMetric(c, string(models.EndpointStateReady), 0)
}

func getMetricValue(state string) int64 {
	return int64(metrics.GetGaugeValue(metrics.EndpointStateCount.WithLabelValues(state)))
}

func assertOnMetric(c *C, state string, expected int64) {
	_, _, line, _ := runtime.Caller(1)

	obtainedValues := make(map[int64]struct{}, 0)
	err := testutils.WaitUntil(func() bool {
		obtained := getMetricValue(state)
		obtainedValues[obtained] = struct{}{}
		return obtained == expected
	}, 10*time.Second)
	if err != nil {
		// We are printing the map here to show every unique obtained metrics
		// value because these values change rapidly and it may be misleading
		// to only show the last obtained value.
		c.Errorf("Metrics assertion failed on line %d for Endpoint state %s: obtained %v, expected %d",
			line, state, obtainedValues, expected)
	}
}
