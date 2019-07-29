package aws

import "context"

// setContext updates the Request to use the passed in context for cancellation.
// Context will also be used for request retry delay.
//
// Creates shallow copy of the http.Request with the WithContext method.
func setRequestContext(ctx context.Context, r *Request) {
	r.context = ctx
	r.HTTPRequest = r.HTTPRequest.WithContext(ctx)
}
