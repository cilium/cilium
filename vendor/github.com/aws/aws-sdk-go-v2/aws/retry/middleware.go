package retry

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddle "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/smithy-go/logging"
	smithymiddle "github.com/aws/smithy-go/middleware"
	"github.com/aws/smithy-go/transport/http"
)

// RequestCloner is a function that can take an input request type and clone the request
// for use in a subsequent retry attempt
type RequestCloner func(interface{}) interface{}

type retryMetadata struct {
	AttemptNum       int
	AttemptTime      time.Time
	MaxAttempts      int
	AttemptClockSkew time.Duration
}

type retryMetadataKey struct{}

// Attempt is a Smithy FinalizeMiddleware that handles retry attempts using the provided
// Retryer implementation
type Attempt struct {
	// Enable the logging of retry attempts performed by the SDK.
	// This will include logging retry attempts, unretryable errors, and when max attempts are reached.
	LogAttempts bool

	retryer       Retryer
	requestCloner RequestCloner
}

// NewAttemptMiddleware returns a new Attempt
func NewAttemptMiddleware(retryer Retryer, requestCloner RequestCloner, optFns ...func(*Attempt)) *Attempt {
	m := &Attempt{retryer: retryer, requestCloner: requestCloner}
	for _, fn := range optFns {
		fn(m)
	}
	return m
}

// ID returns the middleware identifier
func (r *Attempt) ID() string {
	return "Retry"
}

func (r Attempt) logf(logger logging.Logger, classification logging.Classification, format string, v ...interface{}) {
	if !r.LogAttempts {
		return
	}
	logger.Logf(classification, format, v...)
}

// HandleFinalize utilizes the provider Retryer implementation to attempt retries over the next handler
func (r Attempt) HandleFinalize(ctx context.Context, in smithymiddle.FinalizeInput, next smithymiddle.FinalizeHandler) (
	out smithymiddle.FinalizeOutput, metadata smithymiddle.Metadata, err error,
) {
	var attemptNum, retryCount int
	var attemptClockSkew time.Duration

	maxAttempts := r.retryer.MaxAttempts()

	relRetryToken := r.retryer.GetInitialToken()

	logger := smithymiddle.GetLogger(ctx)
	service, operation := awsmiddle.GetServiceID(ctx), awsmiddle.GetOperationName(ctx)

	for {
		attemptNum++

		attemptInput := in
		attemptInput.Request = r.requestCloner(attemptInput.Request)

		attemptCtx := setRetryMetadata(ctx, retryMetadata{
			AttemptNum:       attemptNum,
			AttemptTime:      sdk.NowTime().UTC(),
			MaxAttempts:      maxAttempts,
			AttemptClockSkew: attemptClockSkew,
		})

		if attemptNum > 1 {
			if rewindable, ok := in.Request.(interface{ RewindStream() error }); ok {
				if err := rewindable.RewindStream(); err != nil {
					return out, metadata, fmt.Errorf("failed to rewind transport stream for retry, %w", err)
				}
			}

			r.logf(logger, logging.Debug, "retrying request %s/%s, attempt %d", service, operation, attemptNum)
		}

		out, metadata, reqErr := next.HandleFinalize(attemptCtx, attemptInput)

		if releaseError := relRetryToken(reqErr); releaseError != nil && reqErr != nil {
			return out, metadata, fmt.Errorf("failed to release token after request error, %v", reqErr)
		}

		if reqErr == nil {
			return out, metadata, nil
		}

		retryable := r.retryer.IsErrorRetryable(reqErr)
		if !retryable {
			r.logf(logger, logging.Debug, "request failed with unretryable error %v", reqErr)
			return out, metadata, reqErr
		}

		if maxAttempts > 0 && attemptNum >= maxAttempts {
			r.logf(logger, logging.Debug, "max retry attempts exhausted, max %d", maxAttempts)
			err = &MaxAttemptsError{
				Attempt: attemptNum,
				Err:     reqErr,
			}
			return out, metadata, err
		}

		relRetryToken, err = r.retryer.GetRetryToken(ctx, reqErr)
		if err != nil {
			return out, metadata, err
		}

		retryDelay, err := r.retryer.RetryDelay(attemptNum, reqErr)
		if err != nil {
			return out, metadata, err
		}

		if err = sdk.SleepWithContext(ctx, retryDelay); err != nil {
			err = &aws.RequestCanceledError{Err: err}
			return out, metadata, err
		}

		responseMetadata := awsmiddle.GetResponseMetadata(metadata)
		attemptClockSkew = responseMetadata.AttemptSkew

		retryCount++
	}
}

// MetricsHeader attaches SDK request metric header for retries to the transport
type MetricsHeader struct{}

// ID returns the middleware identifier
func (r *MetricsHeader) ID() string {
	return "RetryMetricsHeader"
}

// HandleFinalize attaches the sdk request metric header to the transport layer
func (r MetricsHeader) HandleFinalize(ctx context.Context, in smithymiddle.FinalizeInput, next smithymiddle.FinalizeHandler) (
	out smithymiddle.FinalizeOutput, metadata smithymiddle.Metadata, err error,
) {
	retryMetadata, ok := getRetryMetadata(ctx)
	if !ok {
		return out, metadata, fmt.Errorf("retry metadata value not found on context")
	}

	const retryMetricHeader = "Amz-Sdk-Request"
	var parts []string

	parts = append(parts, "attempt="+strconv.Itoa(retryMetadata.AttemptNum))
	if retryMetadata.MaxAttempts != 0 {
		parts = append(parts, "max="+strconv.Itoa(retryMetadata.MaxAttempts))
	}

	var ttl time.Time
	if deadline, ok := ctx.Deadline(); ok {
		ttl = deadline
	}

	// Only append the TTL if it can be determined.
	if !ttl.IsZero() && retryMetadata.AttemptClockSkew > 0 {
		const unixTimeFormat = "20060102T150405Z"
		ttl = ttl.Add(retryMetadata.AttemptClockSkew)
		parts = append(parts, "ttl="+ttl.Format(unixTimeFormat))
	}

	switch req := in.Request.(type) {
	case *http.Request:
		req.Header[retryMetricHeader] = append(req.Header[retryMetricHeader][:0], strings.Join(parts, "; "))
	default:
		return out, metadata, fmt.Errorf("unknown transport type %T", req)
	}

	return next.HandleFinalize(ctx, in)
}

// getRetryMetadata retrieves retryMetadata from the context and a bool indicating if it was set
func getRetryMetadata(ctx context.Context) (metadata retryMetadata, ok bool) {
	metadata, ok = ctx.Value(retryMetadataKey{}).(retryMetadata)
	return metadata, ok
}

func setRetryMetadata(ctx context.Context, metadata retryMetadata) context.Context {
	return context.WithValue(ctx, retryMetadataKey{}, metadata)
}

// AddRetryMiddlewaresOptions is the set of options that can be passed to AddRetryMiddlewares for configuring retry
// associated middleware.
type AddRetryMiddlewaresOptions struct {
	Retryer Retryer

	// Enable the logging of retry attempts performed by the SDK.
	// This will include logging retry attempts, unretryable errors, and when max attempts are reached.
	LogRetryAttempts bool
}

// AddRetryMiddlewares adds retry middleware to operation middleware stack
func AddRetryMiddlewares(stack *smithymiddle.Stack, options AddRetryMiddlewaresOptions) error {
	attempt := NewAttemptMiddleware(options.Retryer, http.RequestCloner, func(middleware *Attempt) {
		middleware.LogAttempts = options.LogRetryAttempts
	})

	if err := stack.Finalize.Add(attempt, smithymiddle.After); err != nil {
		return err
	}
	if err := stack.Finalize.Add(&MetricsHeader{}, smithymiddle.After); err != nil {
		return err
	}
	return nil
}
