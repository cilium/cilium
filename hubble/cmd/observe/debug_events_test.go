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
)

func Test_getDebugEventsRequest(t *testing.T) {
	selectorOpts.since = ""
	selectorOpts.until = ""
	req, err := getDebugEventsRequest()
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetDebugEventsRequest{Number: defaults.EventsPrintCount}, req)
	selectorOpts.since = "2021-04-26T01:00:00Z"
	selectorOpts.until = "2021-04-26T01:01:00Z"
	req, err = getDebugEventsRequest()
	require.NoError(t, err)
	since, err := time.Parse(time.RFC3339, selectorOpts.since)
	require.NoError(t, err)
	until, err := time.Parse(time.RFC3339, selectorOpts.until)
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetDebugEventsRequest{
		Number: defaults.EventsPrintCount,
		Since:  timestamppb.New(since),
		Until:  timestamppb.New(until),
	}, req)
}

func Test_getDebugEventsRequestWithoutSince(t *testing.T) {
	selectorOpts.since = ""
	selectorOpts.until = ""
	req, err := getDebugEventsRequest()
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetDebugEventsRequest{Number: defaults.EventsPrintCount}, req)
	selectorOpts.until = "2021-04-26T01:01:00Z"
	req, err = getDebugEventsRequest()
	require.NoError(t, err)
	until, err := time.Parse(time.RFC3339, selectorOpts.until)
	require.NoError(t, err)
	assert.Equal(t, &observerpb.GetDebugEventsRequest{
		Number: defaults.EventsPrintCount,
		Until:  timestamppb.New(until),
	}, req)
}
