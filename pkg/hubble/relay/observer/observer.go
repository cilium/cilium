// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package observer

import (
	"context"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/hubble/relay/queue"
	"github.com/cilium/cilium/pkg/inctimer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func isAvailable(conn poolTypes.ClientConn) bool {
	if conn == nil {
		return false
	}
	switch conn.GetState() {
	case connectivity.Ready, connectivity.Idle:
		return true
	}
	return false
}

func retrieveFlowsFromPeer(
	ctx context.Context,
	client observerpb.ObserverClient,
	req *observerpb.GetFlowsRequest,
	flows chan<- *observerpb.GetFlowsResponse,
) error {
	c, err := client.GetFlows(ctx, req)
	if err != nil {
		return err
	}
	for {
		flow, err := c.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return nil
		case nil:
			select {
			case flows <- flow:
			case <-ctx.Done():
				return nil
			}
		default:
			if status.Code(err) != codes.Canceled {
				return err
			}
			return nil
		}
	}
}

func sortFlows(
	ctx context.Context,
	flows <-chan *observerpb.GetFlowsResponse,
	qlen int,
	bufferDrainTimeout time.Duration,
) <-chan *observerpb.GetFlowsResponse {
	pq := queue.NewPriorityQueue(qlen)
	sortedFlows := make(chan *observerpb.GetFlowsResponse, qlen)

	go func() {
		defer close(sortedFlows)
		bufferTimer, bufferTimerDone := inctimer.New()
		defer bufferTimerDone()
	flowsLoop:
		for {
			select {
			case flow, ok := <-flows:
				if !ok {
					break flowsLoop
				}
				if pq.Len() == qlen {
					f := pq.Pop()
					select {
					case sortedFlows <- f:
					case <-ctx.Done():
						return
					}
				}
				pq.Push(flow)
			case t := <-bufferTimer.After(bufferDrainTimeout):
				// Make sure to drain old flows from the queue when no new
				// flows are received. The bufferDrainTimeout duration is used
				// as a sorting window.
				for _, f := range pq.PopOlderThan(t.Add(-bufferDrainTimeout)) {
					select {
					case sortedFlows <- f:
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
		// drain the queue
		for f := pq.Pop(); f != nil; f = pq.Pop() {
			select {
			case sortedFlows <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	return sortedFlows
}

func nodeStatusError(err error, nodeNames ...string) *observerpb.GetFlowsResponse {
	msg := err.Error()
	if s, ok := status.FromError(err); ok && s.Code() == codes.Unknown {
		msg = s.Message()
	}

	return &observerpb.GetFlowsResponse{
		NodeName: nodeTypes.GetAbsoluteNodeName(),
		Time:     timestamppb.New(time.Now()),
		ResponseTypes: &observerpb.GetFlowsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{
				StateChange: relaypb.NodeState_NODE_ERROR,
				NodeNames:   nodeNames,
				Message:     msg,
			},
		},
	}
}

func nodeStatusEvent(state relaypb.NodeState, nodeNames ...string) *observerpb.GetFlowsResponse {
	return &observerpb.GetFlowsResponse{
		NodeName: nodeTypes.GetAbsoluteNodeName(),
		Time:     timestamppb.New(time.Now()),
		ResponseTypes: &observerpb.GetFlowsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{
				StateChange: state,
				NodeNames:   nodeNames,
			},
		},
	}
}

func aggregateErrors(
	ctx context.Context,
	responses <-chan *observerpb.GetFlowsResponse,
	errorAggregationWindow time.Duration,
) <-chan *observerpb.GetFlowsResponse {
	aggregated := make(chan *observerpb.GetFlowsResponse, cap(responses))

	var flushPending <-chan time.Time
	var pendingResponse *observerpb.GetFlowsResponse

	go func() {
		defer close(aggregated)
	aggregateErrorsLoop:
		for {
			select {
			case response, ok := <-responses:
				if !ok {
					// flush any pending response before exiting
					if pendingResponse != nil {
						select {
						case aggregated <- pendingResponse:
						case <-ctx.Done():
						}
					}
					return
				}

				// any non-error responses are directly forwarded
				current := response.GetNodeStatus()
				if current.GetStateChange() != relaypb.NodeState_NODE_ERROR {
					select {
					case aggregated <- response:
						continue aggregateErrorsLoop
					case <-ctx.Done():
						return
					}
				}

				// either merge with pending or flush it
				if pending := pendingResponse.GetNodeStatus(); pending != nil {
					if current.GetMessage() == pending.GetMessage() {
						pending.NodeNames = append(pending.NodeNames, current.NodeNames...)
						continue aggregateErrorsLoop
					}

					select {
					case aggregated <- pendingResponse:
					case <-ctx.Done():
						return
					}
				}

				pendingResponse = response
				flushPending = inctimer.After(errorAggregationWindow)
			case <-flushPending:
				select {
				case aggregated <- pendingResponse:
					pendingResponse = nil
					flushPending = nil
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}

	}()
	return aggregated
}
