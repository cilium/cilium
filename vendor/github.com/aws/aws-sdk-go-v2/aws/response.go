package aws

// Response provides the response meta data for a SDK API request's response.
type Response struct {
	// TODO these fields should be focused on response, not just embedded request value.
	// Need refactor of request for this to be better.
	Request *Request
}
