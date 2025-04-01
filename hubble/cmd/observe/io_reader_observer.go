// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/pkg/logger"
	"github.com/cilium/cilium/pkg/container"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// IOReaderObserver implements ObserverClient interface. It reads flows
// in jsonpb format from an io.Reader.
type IOReaderObserver struct {
	scanner *bufio.Scanner
}

// NewIOReaderObserver reads flows in jsonpb format from an io.Reader and
// returns a IOReaderObserver that implements the ObserverClient interface.
func NewIOReaderObserver(reader io.Reader) *IOReaderObserver {
	return &IOReaderObserver{
		scanner: bufio.NewScanner(reader),
	}
}

// GetFlows returns flows
func (o *IOReaderObserver) GetFlows(ctx context.Context, in *observerpb.GetFlowsRequest, _ ...grpc.CallOption) (observerpb.Observer_GetFlowsClient, error) {
	return newIOReaderClient(ctx, o.scanner, in)
}

// GetAgentEvents is not implemented, and will throw an error if used.
func (o *IOReaderObserver) GetAgentEvents(_ context.Context, _ *observerpb.GetAgentEventsRequest, _ ...grpc.CallOption) (observerpb.Observer_GetAgentEventsClient, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetAgentEvents not implemented")
}

// GetDebugEvents is not implemented, and will throw an error if used.
func (o *IOReaderObserver) GetDebugEvents(_ context.Context, _ *observerpb.GetDebugEventsRequest, _ ...grpc.CallOption) (observerpb.Observer_GetDebugEventsClient, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetDebugEvents not implemented")
}

// GetNodes is not implemented, and will throw an error if used.
func (o *IOReaderObserver) GetNodes(_ context.Context, _ *observerpb.GetNodesRequest, _ ...grpc.CallOption) (*observerpb.GetNodesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetNodes not implemented")
}

// ServerStatus is not implemented, and will throw an error if used.
func (o *IOReaderObserver) ServerStatus(_ context.Context, _ *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "ServerStatus not implemented")
}

// GetNamespaces is not implemented, and will throw an error if used.
func (o *IOReaderObserver) GetNamespaces(_ context.Context, _ *observerpb.GetNamespacesRequest, _ ...grpc.CallOption) (*observerpb.GetNamespacesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetNamespaces not implemented")
}

// ioReaderClient implements Observer_GetFlowsClient.
type ioReaderClient struct {
	grpc.ClientStream

	scanner        *bufio.Scanner
	discardUnknown bool
	request        *observerpb.GetFlowsRequest
	allow          filters.FilterFuncs
	deny           filters.FilterFuncs

	// Used for --last
	buffer *container.RingBuffer
	resps  []*observerpb.GetFlowsResponse
	// Used for --first/--last
	flowsReturned uint64
}

func newIOReaderClient(ctx context.Context, scanner *bufio.Scanner, request *observerpb.GetFlowsRequest) (*ioReaderClient, error) {
	allow, err := filters.BuildFilterList(ctx, request.GetWhitelist(), filters.DefaultFilters(logging.DefaultSlogLogger))
	if err != nil {
		return nil, err
	}
	deny, err := filters.BuildFilterList(ctx, request.GetBlacklist(), filters.DefaultFilters(logging.DefaultSlogLogger))
	if err != nil {
		return nil, err
	}

	var buf *container.RingBuffer
	// last
	if n := request.GetNumber(); !request.GetFirst() && n != 0 && n != math.MaxUint64 {
		if n > 1_000_000 {
			return nil, fmt.Errorf("--last must be <= 1_000_000, got %d", n)
		}
		buf = container.NewRingBuffer(int(n))
	}
	return &ioReaderClient{
		scanner: scanner,
		request: request,
		allow:   allow,
		deny:    deny,
		buffer:  buf,
	}, nil
}

func (c *ioReaderClient) Recv() (*observerpb.GetFlowsResponse, error) {
	if c.returnedEnoughFlows() {
		return nil, io.EOF
	}

	for c.scanner.Scan() {
		res := c.unmarshalNext()
		if res == nil {
			continue
		}

		switch {
		case c.isLast():
			// store flows in a FIFO buffer, effectively keeping the last N flows
			// until we finish reading from the stream
			c.buffer.Add(res)
		case c.isFirst():
			// track number of flows returned, so we can exit once we've given back N flows
			c.flowsReturned++
			return res, nil
		default: // --all
			return res, nil
		}
	}

	if err := c.scanner.Err(); err != nil {
		return nil, err
	}

	if res := c.popFromLastBuffer(); res != nil {
		return res, nil
	}

	return nil, io.EOF
}

func (c *ioReaderClient) isFirst() bool {
	return c.request.GetFirst() && c.request.GetNumber() != 0 && c.request.GetNumber() != math.MaxUint64
}

func (c *ioReaderClient) isLast() bool {
	return c.buffer != nil && c.request.GetNumber() != math.MaxUint64
}

func (c *ioReaderClient) returnedEnoughFlows() bool {
	return c.request.GetNumber() > 0 && c.flowsReturned >= c.request.GetNumber()
}

func (c *ioReaderClient) popFromLastBuffer() *observerpb.GetFlowsResponse {
	// Handle --last by iterating over our FIFO and returning one item each time.
	if c.isLast() {
		if len(c.resps) == 0 {
			// Iterate over the buffer and store them in a slice, because we cannot
			// index into the ring buffer itself
			// TODO: Add the ability to index into the ring buffer and we could avoid
			// this copy.
			c.buffer.Iterate(func(i any) {
				c.resps = append(c.resps, i.(*observerpb.GetFlowsResponse))
			})
		}

		// return the next element from the buffered results
		if len(c.resps) > int(c.flowsReturned) {
			resp := c.resps[c.flowsReturned]
			c.flowsReturned++
			return resp
		}
	}
	return nil
}

func (c *ioReaderClient) unmarshalNext() *observerpb.GetFlowsResponse {
	var res observerpb.GetFlowsResponse
	err := protojson.UnmarshalOptions{DiscardUnknown: c.discardUnknown}.Unmarshal(c.scanner.Bytes(), &res)
	if err != nil && !c.discardUnknown {
		prevErr := err
		// the error might be that the JSON data contains an unknown field.
		// This can happen we attempting to decode flows generated from a newer
		// Hubble version than the CLI (having introduced a new field). Retry
		// parsing discarding unknown fields and see whether the decoding is
		// successful.
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(c.scanner.Bytes(), &res)
		if err == nil {
			// The error was indeed about a unknown field since we were able to
			// unmarshall without error when discarding unknown fields. Emit a
			// warning message and continue processing discarding unknown
			// fields to avoid logging more than once.
			c.discardUnknown = true
			logger.Logger.Warn("unknown field detected, upgrade the Hubble CLI to get rid of this warning", logfields.Error, prevErr)
		}
	}
	if err != nil {
		line := c.scanner.Text()
		logger.Logger.Warn("Failed to unmarshal json to flow",
			logfields.Error, err,
			logfields.Line, line,
		)
		return nil
	}
	if c.request.GetSince() != nil && c.request.GetSince().AsTime().After(res.GetTime().AsTime()) {
		return nil
	}
	if c.request.GetUntil() != nil && c.request.GetUntil().AsTime().Before(res.GetTime().AsTime()) {
		return nil
	}
	if !filters.Apply(c.allow, c.deny, &v1.Event{Timestamp: res.GetTime(), Event: res.GetFlow()}) {
		return nil
	}
	return &res
}
