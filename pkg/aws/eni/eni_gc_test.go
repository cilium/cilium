// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"time"

	check "github.com/cilium/checkmate"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/logging"
)

func waitForControllerRun(c *check.C, controller *controller.Manager, name string, expectedCount int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		status := controller.GetStatusModel()
		for _, st := range status {
			if st.Name == name && st.Status.SuccessCount == expectedCount {
				return
			}
		}

		select {
		case <-inctimer.After(10 * time.Millisecond):
			continue
		case <-ctx.Done():
			c.Errorf("timed out waiting for controller %q to reach %d successful runs", name, expectedCount)
			break
		}
	}
}

func (e *ENISuite) TestStartENIGarbageCollector(c *check.C) {
	level := logging.GetLevel(logging.DefaultLogger)
	logging.SetLogLevelToDebug()
	defer logging.SetLogLevel(level)

	tags := map[string]string{
		"cilium-managed": "true",
	}

	ec2api := ec2mock.NewAPI(subnets, vpcs, securityGroups)
	c.Assert(ec2api, check.Not(check.IsNil))

	untaggedENIs := map[string]bool{}
	for i := 0; i < 8; i++ {
		eniID, _, err := ec2api.CreateNetworkInterface(context.TODO(), 0, "subnet-1", "desc", []string{"sg-1", "sg-2"}, false)
		c.Assert(err, check.IsNil)
		untaggedENIs[eniID] = true
	}

	createTaggedENI := func() string {
		eniID, _, err := ec2api.CreateNetworkInterface(context.TODO(), 0, "subnet-2", "desc", []string{"sg-1", "sg-2"}, false)
		c.Assert(err, check.IsNil)
		err = ec2api.TagENI(context.TODO(), eniID, tags)
		c.Assert(err, check.IsNil)
		return eniID
	}
	for i := 0; i < 8; i++ {
		createTaggedENI()
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	StartENIGarbageCollector(ctx, ec2api, GarbageCollectionParams{
		RunInterval:    0, // for testing, we're triggering the controller manually
		MaxPerInterval: 4,
		ENITags:        tags,
	})

	waitForControllerRun(c, controllerManager, gcENIControllerName, 1)

	// after the first run, no ENIs should have been deleted
	enis, err := ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	c.Assert(err, check.IsNil)
	c.Assert(enis, check.HasLen, 16)

	// Delete first batch of ENIs (4 ENIs should be deleted)
	controllerManager.TriggerController(gcENIControllerName)
	waitForControllerRun(c, controllerManager, gcENIControllerName, 2)

	enis, err = ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	c.Assert(err, check.IsNil)
	c.Assert(enis, check.HasLen, 12)

	// Create a new unattached ENI (it should _not_ be deleted in the next round)
	newENI := createTaggedENI()

	// Trigger deletion of second batch of ENIs (4 ENIs should be deleted)
	controllerManager.TriggerController(gcENIControllerName)
	waitForControllerRun(c, controllerManager, gcENIControllerName, 3)

	// Now 8 untagged and 1 newENI should be the only ENIs left
	enis, err = ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	c.Assert(err, check.IsNil)
	c.Assert(enis, check.HasLen, 9)
	for _, eni := range enis {
		if eni != newENI && !untaggedENIs[eni] {
			c.Errorf("ENI not garbage collected: %s", eni)
		}
	}

	// Attach newENI, this means it can no longer be garbage collected
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 1, "i-1", newENI)
	c.Assert(err, check.IsNil)

	controllerManager.TriggerController(gcENIControllerName)
	waitForControllerRun(c, controllerManager, gcENIControllerName, 4)

	// All remaining ENIs should be unattached ones
	enis, err = ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	c.Assert(err, check.IsNil)
	c.Assert(enis, check.HasLen, 8)
	for _, eni := range enis {
		if !untaggedENIs[eni] {
			c.Errorf("ENI not garbage collected: %s", eni)
		}
	}

	// Check the attached ENI still exists
	ec2api.TagENI(context.TODO(), newENI, tags)
	c.Assert(err, check.IsNil)
}
