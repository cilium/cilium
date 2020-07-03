package ec2metadata

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
)

// A tokenProvider struct provides access to EC2Metadata client
// and atomic instance of a token, along with configuredTTL for it.
// tokenProvider also provides an atomic flag to disable the
// fetch token operation.
// The disabled member will use 0 as false, and 1 as true.
type tokenProvider struct {
	client        *Client
	token         atomic.Value
	configuredTTL time.Duration
	disabled      uint32
}

// A ec2Token struct helps use of token in EC2 Metadata service ops
type ec2Token struct {
	token string
	aws.Credentials
}

// newTokenProvider provides a pointer to a tokenProvider instance
func newTokenProvider(c *Client, duration time.Duration) *tokenProvider {
	return &tokenProvider{client: c, configuredTTL: duration}
}

// fetchTokenHandler fetches token for EC2Metadata service client by default.
func (t *tokenProvider) fetchTokenHandler(r *aws.Request) {

	// short-circuits to insecure data flow if tokenProvider is disabled.
	if v := atomic.LoadUint32(&t.disabled); v == 1 {
		return
	}

	if ec2Token, ok := t.token.Load().(ec2Token); ok && !ec2Token.Expired() {
		r.HTTPRequest.Header.Set(tokenHeader, ec2Token.token)
		return
	}

	output, err := t.client.getToken(r.Context(), t.configuredTTL)
	if err != nil {
		// change the disabled flag on token provider to true, when error is request timeout error.
		if rf, ok := err.(awserr.RequestFailure); ok {
			switch rf.StatusCode() {
			case http.StatusForbidden,
				http.StatusNotFound,
				http.StatusMethodNotAllowed:

				atomic.StoreUint32(&t.disabled, 1)

			case http.StatusBadRequest:
				r.Error = rf
			}

			// Check if request timed out while waiting for response
			var re *aws.RequestSendError
			var ce *aws.RequestCanceledError
			if errors.As(rf, &re) || errors.As(rf, &ce) {
				atomic.StoreUint32(&t.disabled, 1)
			}
		}
		return
	}

	newToken := ec2Token{
		token: output.Token,
	}
	newToken.CanExpire = true
	newToken.Expires = time.Now().Add(output.TTL).Add(-ttlExpirationWindow)
	t.token.Store(newToken)
	if ec2Token, ok := t.token.Load().(ec2Token); ok {
		// Inject token header to the request.
		r.HTTPRequest.Header.Set(tokenHeader, ec2Token.token)
	}
}

// enableTokenProviderHandler enables the token provider
func (t *tokenProvider) enableTokenProviderHandler(r *aws.Request) {
	// If the error code status is 401, we enable the token provider
	if e, ok := r.Error.(awserr.RequestFailure); ok && e != nil &&
		e.StatusCode() == http.StatusUnauthorized {
		atomic.StoreUint32(&t.disabled, 0)
	}
}
