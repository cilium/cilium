// Copyright (c) The go-grpc-middleware Authors.
// Licensed under the Apache License 2.0.

package timeout

import (
	"context"
	"time"

	"google.golang.org/grpc"
)

// UnaryClientInterceptor returns a new unary client interceptor that sets a timeout on the request context.
func UnaryClientInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		timedCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoker(timedCtx, method, req, reply, cc, opts...)
	}
}
