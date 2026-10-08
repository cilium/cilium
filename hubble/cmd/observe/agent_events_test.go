// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestAgentEventSubTypeMap(t *testing.T) {
	// Make sure to keep agent event sub-types maps in sync. See
	// agentEventSubtypes godoc for details.
	require.Len(t, agentEventSubtypes, len(monitorAPI.AgentNotifications))
	for _, v := range agentEventSubtypes {
		require.Contains(t, monitorAPI.AgentNotifications, v)
	}
	agentEventSubtypesContainsValue := func(an monitorAPI.AgentNotification) bool {
		for _, v := range agentEventSubtypes {
			if v == an {
				return true
			}
		}
		return false
	}
	for k := range monitorAPI.AgentNotifications {
		require.True(t, agentEventSubtypesContainsValue(k))
	}
}

func Test_getAgentEventsRequest(t *testing.T) {
	selectorOpts.since = ""
	selectorOpts.until = ""
	req, err := getAgentEventsRequest()
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetAgentEventsRequest{Number: defaults.EventsPrintCount}, req)
	selectorOpts.since = "2021-04-26T00:00:00Z"
	selectorOpts.until = "2021-04-26T00:01:00Z"
	req, err = getAgentEventsRequest()
	require.NoError(t, err)
	since, err := time.Parse(time.RFC3339, selectorOpts.since)
	require.NoError(t, err)
	until, err := time.Parse(time.RFC3339, selectorOpts.until)
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetAgentEventsRequest{
		Number: defaults.EventsPrintCount,
		Since:  timestamppb.New(since),
		Until:  timestamppb.New(until),
	}, req)
}

func Test_getAgentEventsRequestWithoutSince(t *testing.T) {
	selectorOpts.since = ""
	selectorOpts.until = ""
	req, err := getAgentEventsRequest()
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetAgentEventsRequest{Number: defaults.EventsPrintCount}, req)
	selectorOpts.until = "2021-04-26T00:01:00Z"
	req, err = getAgentEventsRequest()
	require.NoError(t, err)
	until, err := time.Parse(time.RFC3339, selectorOpts.until)
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetAgentEventsRequest{
		Number: defaults.EventsPrintCount,
		Until:  timestamppb.New(until),
	}, req)
}
