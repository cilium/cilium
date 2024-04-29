// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/logging"
)

func waitForControllerRun(t *testing.T, controller *controller.Manager, name string, expectedCount int64) {
	t.Helper()
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
			t.Errorf("timed out waiting for controller %q to reach %d successful runs", name, expectedCount)
			break
		}
	}
}

func TestStartENIGarbageCollector(t *testing.T) {
	level := logging.GetLevel(logging.DefaultLogger)
	logging.SetLogLevelToDebug()
	defer logging.SetLogLevel(level)

	tags := map[string]string{
		"cilium-managed": "true",
	}

	ec2api := ec2mock.NewAPI(subnets, vpcs, securityGroups)
	require.NotNil(t, ec2api)

	untaggedENIs := map[string]bool{}
	for i := 0; i < 8; i++ {
		eniID, _, err := ec2api.CreateNetworkInterface(context.TODO(), 0, "subnet-1", "desc", []string{"sg-1", "sg-2"}, false)
		require.NoError(t, err)
		untaggedENIs[eniID] = true
	}

	createTaggedENI := func() string {
		eniID, _, err := ec2api.CreateNetworkInterface(context.TODO(), 0, "subnet-2", "desc", []string{"sg-1", "sg-2"}, false)
		require.NoError(t, err)
		err = ec2api.TagENI(context.TODO(), eniID, tags)
		require.NoError(t, err)
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

	waitForControllerRun(t, controllerManager, gcENIControllerName, 1)

	// after the first run, no ENIs should have been deleted
	enis, err := ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	require.NoError(t, err)
	require.Len(t, enis, 16)

	// Delete first batch of ENIs (4 ENIs should be deleted)
	controllerManager.TriggerController(gcENIControllerName)
	waitForControllerRun(t, controllerManager, gcENIControllerName, 2)

	enis, err = ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	require.NoError(t, err)
	require.Len(t, enis, 12)

	// Create a new unattached ENI (it should _not_ be deleted in the next round)
	newENI := createTaggedENI()

	// Trigger deletion of second batch of ENIs (4 ENIs should be deleted)
	controllerManager.TriggerController(gcENIControllerName)
	waitForControllerRun(t, controllerManager, gcENIControllerName, 3)

	// Now 8 untagged and 1 newENI should be the only ENIs left
	enis, err = ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	require.NoError(t, err)
	require.Len(t, enis, 9)
	for _, eni := range enis {
		if eni != newENI && !untaggedENIs[eni] {
			t.Errorf("ENI not garbage collected: %s", eni)
		}
	}

	// Attach newENI, this means it can no longer be garbage collected
	_, err = ec2api.AttachNetworkInterface(context.TODO(), 1, "i-1", newENI)
	require.NoError(t, err)

	controllerManager.TriggerController(gcENIControllerName)
	waitForControllerRun(t, controllerManager, gcENIControllerName, 4)

	// All remaining ENIs should be unattached ones
	enis, err = ec2api.GetDetachedNetworkInterfaces(context.TODO(), nil, 25)
	require.NoError(t, err)
	require.Len(t, enis, 8)
	for _, eni := range enis {
		if !untaggedENIs[eni] {
			t.Errorf("ENI not garbage collected: %s", eni)
		}
	}

	// Check the attached ENI still exists
	ec2api.TagENI(context.TODO(), newENI, tags)
	require.NoError(t, err)
}
