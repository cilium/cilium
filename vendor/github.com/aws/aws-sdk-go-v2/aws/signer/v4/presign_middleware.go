package v4

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/awslabs/smithy-go/middleware"
	smithyHTTP "github.com/awslabs/smithy-go/transport/http"
)

// HTTPPresigner is an interface to a SigV4 signer that can sign create a
// presigned URL for a HTTP requests.
type HTTPPresigner interface {
	PresignHTTP(
		ctx context.Context, credentials aws.Credentials, r *http.Request,
		payloadHash string, service string, region string, signingTime time.Time,
	) (url string, signedHeader http.Header, err error)
}

// PresignedHTTPRequest provides the URL and signed headers that are included
// in the presigned URL.
type PresignedHTTPRequest struct {
	URL          string
	Method       string
	SignedHeader http.Header
}

// PresignHTTPRequestMiddleware provides the Finalize middleware for creating a
// presigned URL for an HTTP request.
//
// Will short circuit the middleware stack and not forward onto the next
// Finalize handler.
type PresignHTTPRequestMiddleware struct {
	credentialsProvider aws.CredentialsProvider
	presigner           HTTPPresigner
}

// NewPresignHTTPRequestMiddleware returns a new PresignHTTPRequestMiddleware
// initialized with the presigner.
func NewPresignHTTPRequestMiddleware(provider aws.CredentialsProvider, presigner HTTPPresigner) *PresignHTTPRequestMiddleware {
	return &PresignHTTPRequestMiddleware{
		credentialsProvider: provider,
		presigner:           presigner,
	}
}

// ID provides the middleware ID.
func (*PresignHTTPRequestMiddleware) ID() string { return "PresignHTTPRequestMiddleware" }

// HandleFinalize will take the provided input and create a presigned url for
// the http request using the SigV4 presign authentication scheme.
//
// Since the signed request is not a valid HTTP request
func (s *PresignHTTPRequestMiddleware) HandleFinalize(
	ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler,
) (
	out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
) {
	req, ok := in.Request.(*smithyHTTP.Request)
	if !ok {
		return out, metadata, &SigningError{
			Err: fmt.Errorf("unexpected request middleware type %T", in.Request),
		}
	}

	httpReq := req.Build(ctx)
	if !haveCredentialProvider(s.credentialsProvider) {
		out.Result = &PresignedHTTPRequest{
			URL:          httpReq.URL.String(),
			Method:       httpReq.Method,
			SignedHeader: http.Header{},
		}

		return out, metadata, nil
	}

	signingName := awsmiddleware.GetSigningName(ctx)
	signingRegion := awsmiddleware.GetSigningRegion(ctx)
	payloadHash := GetPayloadHash(ctx)
	if len(payloadHash) == 0 {
		return out, metadata, &SigningError{
			Err: fmt.Errorf("computed payload hash missing from context"),
		}
	}

	credentials, err := s.credentialsProvider.Retrieve(ctx)
	if err != nil {
		return out, metadata, &SigningError{
			Err: fmt.Errorf("failed to retrieve credentials: %w", err),
		}
	}

	u, h, err := s.presigner.PresignHTTP(ctx, credentials,
		httpReq, payloadHash, signingName, signingRegion, sdk.NowTime())
	if err != nil {
		return out, metadata, &SigningError{
			Err: fmt.Errorf("failed to sign http request, %w", err),
		}
	}

	out.Result = &PresignedHTTPRequest{
		URL:          u,
		Method:       httpReq.Method,
		SignedHeader: h,
	}

	return out, metadata, nil
}
