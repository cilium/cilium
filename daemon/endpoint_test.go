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
	"runtime"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	apiEndpoint "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
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
	_, code, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	// Endpoint was created with invalid data; should transition from
	// WaitForIdentity -> Invalid.
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)
	assertOnMetric(c, string(models.EndpointStateInvalid), 0)

	// Endpoint is created with inital label as well as disallowed
	// reserved:world label.
	epTemplate.Labels = append(epTemplate.Labels, "reserved:init")
	_, code, err = ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, ErrorMatches, "not allowed to add reserved labels:.+")
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	// Endpoint was created with invalid data; should transition from
	// WaitForIdentity -> Invalid.
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)
	assertOnMetric(c, string(models.EndpointStateInvalid), 0)
}

func (ds *DaemonSuite) TestEndpointAddInvalidLabel(c *C) {
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)

	epTemplate := getEPTemplate(c, ds.d)
	epTemplate.Labels = []string{"reserved:foo"}
	_, code, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, Not(IsNil))
	c.Assert(code, Equals, apiEndpoint.PutEndpointIDInvalidCode)

	// Endpoint was created with invalid data; should transition from
	// WaitForIdentity -> Invalid.
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)
	assertOnMetric(c, string(models.EndpointStateInvalid), 0)
}

func (ds *DaemonSuite) TestEndpointAddNoLabels(c *C) {
	assertOnMetric(c, string(models.EndpointStateWaitingForIdentity), 0)

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(c, ds.d)
	_, _, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, IsNil)

	// Endpoint enters WaitingToRegenerate as it has its labels updated during
	// creation.
	assertOnMetric(c, string(models.EndpointStateWaitingToRegenerate), 1)

	expectedLabels := labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	// Check that the endpoint has the reserved:init label.
	ep, err := endpointmanager.Lookup(endpointid.NewIPPrefixID(net.ParseIP(epTemplate.Addressing.IPV4)))
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

	// Endpoint should transition from WaitingToRegenerate -> Ready.
	assertOnMetric(c, string(models.EndpointStateWaitingToRegenerate), 0)
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
	_, _, err := ds.d.createEndpoint(cancelledContext, epTemplate)
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

type EndpointDeadlockEvent struct {
	ep           *endpoint.Endpoint
	deadlockChan chan struct{}
}

var (
	deadlockTimeout     = 2 * time.Second
	deadlockTestTimeout = 3*deadlockTimeout + 1*time.Second
)

func (n *EndpointDeadlockEvent) Handle(ifc chan interface{}) {
	// We need to sleep here so that we are consuming an event off the queue,
	// but not acquiring the lock yet.
	// There isn't much of a better way to ensure that an Event is being
	// processed off of the EventQueue, but hasn't acquired the Endpoint's
	// lock *before* we call deleteEndpointQuiet (see below test).
	close(n.deadlockChan)
	time.Sleep(deadlockTimeout)
	n.ep.UnconditionalLock()
	n.ep.Unlock()
}

// This unit test is a bit weird - see
// https://github.com/cilium/cilium/pull/8687 .
func (ds *DaemonSuite) TestEndpointEventQueueDeadlockUponDeletion(c *C) {
	// Need to modify global configuration (hooray!), change back when test is
	// done.
	oldQueueSize := option.Config.EndpointQueueSize
	option.Config.EndpointQueueSize = 1
	defer func() {
		option.Config.EndpointQueueSize = oldQueueSize
	}()

	// Create the endpoint without any labels.
	epTemplate := getEPTemplate(c, ds.d)
	ep, _, err := ds.d.createEndpoint(context.TODO(), epTemplate)
	c.Assert(err, IsNil)
	c.Assert(ep, Not(IsNil))

	// In case deadlock occurs, provide a timeout of 3 (number of events) *
	// deadlockTimeout + 1 seconds to ensure that we are actually testing for
	// deadlock, and not prematurely exiting, and also so the test suite doesn't
	// hang forever.
	ctx, cancel := context.WithTimeout(context.Background(), deadlockTestTimeout)
	defer cancel()

	// Create three events that go on the endpoint's EventQueue. We need three
	// events because the first event enqueued immediately is consumed off of
	// the queue; the second event is put onto the queue (which has length of
	// one), and the third queue is waiting for the queue's buffer to not be
	// full (e.g., the first event is finished processing). If the first event
	// gets stuck processing forever due to deadlock, then the third event
	// will never be consumed, and the endpoint's EventQueue will never be
	// closed because Enqueue gets stuck.
	ev1Ch := make(chan struct{})
	ev2Ch := make(chan struct{})
	ev3Ch := make(chan struct{})

	ev := eventqueue.NewEvent(&EndpointDeadlockEvent{
		ep:           ep,
		deadlockChan: ev1Ch,
	})

	ev2 := eventqueue.NewEvent(&EndpointDeadlockEvent{
		ep:           ep,
		deadlockChan: ev2Ch,
	})

	ev3 := eventqueue.NewEvent(&EndpointDeadlockEvent{
		ep:           ep,
		deadlockChan: ev3Ch,
	})

	ev2EnqueueCh := make(chan struct{})

	go func() {
		_, err := ep.EventQueue.Enqueue(ev)
		c.Assert(err, IsNil)
		_, err = ep.EventQueue.Enqueue(ev2)
		c.Assert(err, IsNil)
		close(ev2EnqueueCh)
		_, err = ep.EventQueue.Enqueue(ev3)
		c.Assert(err, IsNil)
	}()

	// Ensure that the second event is enqueued before proceeding further, as
	// we need to assume that at least one event is being processed, and another
	// one is pushed onto the endpoint's EventQueue.
	<-ev2EnqueueCh
	epDelComplete := make(chan struct{})

	// Launch endpoint deletion async so that we do not deadlock (which is what
	// this unit test is designed to test).
	go func(ch chan struct{}) {
		errors := ds.d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{})
		c.Assert(errors, Not(IsNil))
		epDelComplete <- struct{}{}
	}(epDelComplete)

	select {
	case <-ctx.Done():
		c.Log("endpoint deletion did not complete in time")
		c.Fail()
	case <-epDelComplete:
		// Success, do nothing.
	}
}
