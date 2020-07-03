// Package defaults is a collection of helpers to retrieve the SDK's default
// configuration and handlers.
//
// Generally this package shouldn't be used directly, but external.Config
// instead. This package is useful when you need to reset the defaults
// of a service client to the SDK defaults before setting
// additional parameters.
package defaults

import (
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
)

// Logger returns a Logger which will write log messages to stdout, and
// use same formatting runes as the stdlib log.Logger
func Logger() aws.Logger {
	return &defaultLogger{
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// A defaultLogger provides a minimalistic logger satisfying the Logger interface.
type defaultLogger struct {
	logger *log.Logger
}

// Log logs the parameters to the stdlib logger. See log.Println.
func (l defaultLogger) Log(args ...interface{}) {
	l.logger.Println(args...)
}

// Config returns the default configuration without credentials.
// To retrieve a config with credentials also included use
// `defaults.Get().Config` instead.
//
// Generally you shouldn't need to use this method directly, but
// is available if you need to reset the configuration of an
// existing service client.
func Config() aws.Config {
	return aws.Config{
		EndpointResolver: endpoints.NewDefaultResolver(),
		Credentials:      aws.AnonymousCredentials,
		HTTPClient:       HTTPClient(),
		Logger:           Logger(),
		Handlers:         Handlers(),
	}
}

// HTTPClient will return a new HTTP Client configured for the SDK.
//
// Does not use http.DefaultClient nor http.DefaultTransport.
func HTTPClient() aws.HTTPClient {
	return aws.NewBuildableHTTPClient()
}

// Handlers returns the default request handlers.
//
// Generally you shouldn't need to use this method directly, but
// is available if you need to reset the request handlers of an
// existing service client.
func Handlers() aws.Handlers {
	var handlers aws.Handlers

	handlers.Validate.PushBackNamed(ValidateEndpointHandler)
	handlers.Validate.PushBackNamed(ValidateParametersHandler)
	handlers.Validate.AfterEachFn = aws.HandlerListStopOnError
	handlers.Build.PushBackNamed(SDKVersionUserAgentHandler)
	handlers.Build.PushBackNamed(AddHostExecEnvUserAgentHander)
	handlers.Build.PushFrontNamed(RequestInvocationIDHeaderHandler)
	handlers.Build.AfterEachFn = aws.HandlerListStopOnError
	handlers.Sign.PushBackNamed(BuildContentLengthHandler)
	handlers.Sign.PushFrontNamed(RetryMetricHeaderHandler)
	handlers.Send.PushBackNamed(ValidateReqSigHandler)
	handlers.Send.PushBackNamed(SendHandler)
	handlers.Send.PushBackNamed(AttemptClockSkewHandler)
	handlers.ShouldRetry.PushBackNamed(RetryableCheckHandler)
	handlers.ValidateResponse.PushBackNamed(ValidateResponseHandler)

	return handlers
}
