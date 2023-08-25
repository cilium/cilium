// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// traceparentHeader is a HTTP header defined in the W3C Trace Context specification:
// https://www.w3.org/TR/trace-context/
// It identifies the incoming request in a tracing system and contains, among
// other things, the trace ID.
const traceparentHeader = "traceparent"

func extractTraceContext(record *accesslog.LogRecord) *flowpb.TraceContext {
	if record == nil {
		return nil
	}
	switch {
	case record.HTTP != nil:
		traceID := traceIDFromHTTPHeader(record.HTTP.Headers)
		if traceID == "" {
			return nil
		}
		return &flowpb.TraceContext{
			Parent: &flowpb.TraceParent{
				TraceId: traceID,
			},
		}
	case record.Kafka != nil:
		// TODO
		return nil
	default:
		return nil
	}
}

func traceIDFromHTTPHeader(h http.Header) string {
	if h.Get(traceparentHeader) == "" {
		// return early if no trace parent header is present to avoid
		// unnecessary processing and memory allocation
		return ""
	}

	tc := propagation.TraceContext{}
	sp := trace.SpanContextFromContext(
		tc.Extract(
			context.Background(),
			propagation.HeaderCarrier(h),
		),
	)
	if sp.HasTraceID() {
		return sp.TraceID().String()
	}
	return ""
}
