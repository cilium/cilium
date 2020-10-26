// Copyright 2020 Authors of Cilium
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

package observer

import (
	"context"
	"io"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/hubble/relay/queue"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
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
			case t := <-time.After(bufferDrainTimeout):
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
		NodeName: nodeTypes.GetName(),
		Time:     ptypes.TimestampNow(),
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
		NodeName: nodeTypes.GetName(),
		Time:     ptypes.TimestampNow(),
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
				flushPending = time.After(errorAggregationWindow)
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
