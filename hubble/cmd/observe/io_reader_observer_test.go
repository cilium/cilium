// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/pkg/logger"
)

func Test_getFlowsBasic(t *testing.T) {
	flows := []*observerpb.GetFlowsResponse{{}, {}, {}}
	var flowStrings []string
	for _, f := range flows {
		b, err := f.MarshalJSON()
		require.NoError(t, err)
		flowStrings = append(flowStrings, string(b))
	}
	server := NewIOReaderObserver(strings.NewReader(strings.Join(flowStrings, "\n") + "\n"))
	req := observerpb.GetFlowsRequest{}
	client, err := server.GetFlows(t.Context(), &req)
	require.NoError(t, err)
	for range flows {
		_, err = client.Recv()
		require.NoError(t, err)
	}
	_, err = client.Recv()
	assert.Equal(t, io.EOF, err)
}

func Test_getFlowsTimeRange(t *testing.T) {
	flows := []*observerpb.GetFlowsResponse{
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}},
			Time:          &timestamppb.Timestamp{Seconds: 0},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}},
			Time:          &timestamppb.Timestamp{Seconds: 100},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_ERROR}},
			Time:          &timestamppb.Timestamp{Seconds: 200},
		},
	}
	var flowStrings []string
	for _, f := range flows {
		b, err := f.MarshalJSON()
		require.NoError(t, err)
		flowStrings = append(flowStrings, string(b))
	}
	server := NewIOReaderObserver(strings.NewReader(strings.Join(flowStrings, "\n") + "\n"))
	req := observerpb.GetFlowsRequest{
		Since: &timestamppb.Timestamp{Seconds: 50},
		Until: &timestamppb.Timestamp{Seconds: 150},
	}
	client, err := server.GetFlows(t.Context(), &req)
	require.NoError(t, err)
	res, err := client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[1], res)
	_, err = client.Recv()
	assert.Equal(t, io.EOF, err)
}

func Test_getFlowsLast(t *testing.T) {
	flows := []*observerpb.GetFlowsResponse{
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}},
			Time:          &timestamppb.Timestamp{Seconds: 0},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}},
			Time:          &timestamppb.Timestamp{Seconds: 100},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_ERROR}},
			Time:          &timestamppb.Timestamp{Seconds: 200},
		},
	}
	var flowStrings []string
	for _, f := range flows {
		b, err := f.MarshalJSON()
		require.NoError(t, err)
		flowStrings = append(flowStrings, string(b))
	}
	server := NewIOReaderObserver(strings.NewReader(strings.Join(flowStrings, "\n") + "\n"))
	req := observerpb.GetFlowsRequest{
		Number: 2,
		First:  false,
	}
	client, err := server.GetFlows(t.Context(), &req)
	require.NoError(t, err)
	res, err := client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[1], res)
	res, err = client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[2], res)
	_, err = client.Recv()
	assert.Equal(t, io.EOF, err)
}

func Test_getFlowsFirst(t *testing.T) {
	flows := []*observerpb.GetFlowsResponse{
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}},
			Time:          &timestamppb.Timestamp{Seconds: 0},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}},
			Time:          &timestamppb.Timestamp{Seconds: 100},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_ERROR}},
			Time:          &timestamppb.Timestamp{Seconds: 200},
		},
	}
	var flowStrings []string
	for _, f := range flows {
		b, err := f.MarshalJSON()
		require.NoError(t, err)
		flowStrings = append(flowStrings, string(b))
	}
	server := NewIOReaderObserver(strings.NewReader(strings.Join(flowStrings, "\n") + "\n"))
	req := observerpb.GetFlowsRequest{
		Number: 2,
		First:  true,
	}
	client, err := server.GetFlows(t.Context(), &req)
	require.NoError(t, err)
	res, err := client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[0], res)
	res, err = client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[1], res)
	_, err = client.Recv()
	assert.Equal(t, io.EOF, err)
}

func Test_getFlowsFilter(t *testing.T) {
	flows := []*observerpb.GetFlowsResponse{
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}},
			Time:          &timestamppb.Timestamp{Seconds: 0},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}},
			Time:          &timestamppb.Timestamp{Seconds: 100},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_ERROR}},
			Time:          &timestamppb.Timestamp{Seconds: 200},
		},
	}
	var flowStrings []string
	for _, f := range flows {
		b, err := f.MarshalJSON()
		require.NoError(t, err)
		flowStrings = append(flowStrings, string(b))
	}
	server := NewIOReaderObserver(strings.NewReader(strings.Join(flowStrings, "\n") + "\n"))
	req := observerpb.GetFlowsRequest{
		Whitelist: []*flowpb.FlowFilter{
			{
				Verdict: []flowpb.Verdict{flowpb.Verdict_FORWARDED, flowpb.Verdict_ERROR},
			},
		},
	}
	client, err := server.GetFlows(t.Context(), &req)
	require.NoError(t, err)
	res, err := client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[0], res)
	res, err = client.Recv()
	require.NoError(t, err)
	assert.Equal(t, flows[2], res)
	_, err = client.Recv()
	assert.Equal(t, io.EOF, err)
}

func Test_UnknownField(t *testing.T) {
	flows := []*observerpb.GetFlowsResponse{
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}},
			Time:          &timestamppb.Timestamp{Seconds: 0},
		},
		{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}},
			Time:          &timestamppb.Timestamp{Seconds: 100},
		},
	}

	var sb strings.Builder
	for _, f := range flows {
		b, err := f.MarshalJSON()
		require.NoError(t, err)
		s := strings.Replace(string(b), `"flow":{`, `"flow":{"foo":42,`, 1)
		sb.WriteString(s + "\n")
	}
	// server and client setup.
	server := NewIOReaderObserver(strings.NewReader(sb.String()))
	client, err := server.GetFlows(t.Context(), &observerpb.GetFlowsRequest{})
	require.NoError(t, err)
	// logger setup.
	logger.Initialize(slog.NewTextHandler(&sb, nil))
	sb.Reset()

	// ensure that we see the first flow.
	res, err := client.Recv()
	require.NoError(t, err)
	require.Equal(t, flows[0], res)
	// check that we logged something the first time we've seen an unknown
	// field.
	require.Contains(t, sb.String(), "unknown field detected")
	sb.Reset()
	// ensure that we see the second flow.
	res, err = client.Recv()
	require.NoError(t, err)
	require.Equal(t, flows[1], res)
	// check that we didn't log the second time we've seen an unknown field.
	require.Empty(t, sb.String())
	// ensure we're at the end of the stream.
	_, err = client.Recv()
	require.Equal(t, io.EOF, err)
}
