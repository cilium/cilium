// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// traceparentHeader is a HTTP header defined in the W3C Trace Context specification:
// https://www.w3.org/TR/trace-context/
// It identifies the incoming request in a tracing system and contains, among
// other things, the trace ID.
const traceparentHeader = "traceparent"

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
