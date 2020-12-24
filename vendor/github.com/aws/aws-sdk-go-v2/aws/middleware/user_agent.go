package middleware

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const execEnvVar = `AWS_EXECUTION_ENV`
const execEnvUAKey = `exec-env`

// requestUserAgent is a build middleware that set the User-Agent for the request.
type requestUserAgent struct {
	uab *smithyhttp.UserAgentBuilder
}

// newRequestUserAgent returns a new requestUserAgent which will set the User-Agent for the request.
//
// Default Example:
//   aws-sdk-go/2.3.4 GOOS/linux GOARCH/amd64 GO/go1.14
func newRequestUserAgent() *requestUserAgent {
	uab := smithyhttp.NewUserAgentBuilder()
	uab.AddKeyValue(aws.SDKName, aws.SDKVersion)
	uab.AddKeyValue("GOOS", runtime.GOOS)
	uab.AddKeyValue("GOARCH", runtime.GOARCH)
	uab.AddKeyValue("GO", runtime.Version())
	if ev := os.Getenv(execEnvVar); len(ev) > 0 {
		uab.AddKeyValue(execEnvUAKey, ev)
	}
	return &requestUserAgent{uab: uab}
}

// AddUserAgentKey retrieves a requestUserAgent from the provided stack, or initializes one.
func AddUserAgentKey(key string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		requestUserAgent, err := getOrAddRequestUserAgent(stack)
		if err != nil {
			return err
		}
		requestUserAgent.AddKey(key)
		return nil
	}
}

// AddUserAgentKeyValue retrieves a requestUserAgent from the provided stack, or initializes one.
func AddUserAgentKeyValue(key, value string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		requestUserAgent, err := getOrAddRequestUserAgent(stack)
		if err != nil {
			return err
		}
		requestUserAgent.AddKeyValue(key, value)
		return nil
	}
}

func getOrAddRequestUserAgent(stack *middleware.Stack) (*requestUserAgent, error) {
	id := (*requestUserAgent)(nil).ID()
	bm, ok := stack.Build.Get(id)
	if !ok {
		bm = newRequestUserAgent()
		err := stack.Build.Add(bm, middleware.After)
		if err != nil {
			return nil, err
		}
	}

	requestUserAgent, ok := bm.(*requestUserAgent)
	if !ok {
		return nil, fmt.Errorf("%T for %s middleware did not match expected type", bm, id)
	}

	return requestUserAgent, nil
}

// AddKey adds the component identified by name to the User-Agent string.
func (u *requestUserAgent) AddKey(key string) {
	u.uab.AddKey(key)
}

// AddKeyValue adds the key identified by the given name and value to the User-Agent string.
func (u *requestUserAgent) AddKeyValue(key, value string) {
	u.uab.AddKeyValue(key, value)
}

// ID the name of the middleware.
func (u *requestUserAgent) ID() string {
	return "UserAgent"
}

// HandleBuild adds or appends the constructed user agent to the request.
func (u *requestUserAgent) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (
	out middleware.BuildOutput, metadata middleware.Metadata, err error,
) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in)
	}

	const userAgent = "User-Agent"
	var current string
	if v := req.Header[userAgent]; len(v) > 0 {
		current = v[0]
	}
	if v := u.uab.Build(); len(current) > 0 {
		current = v + " " + current
	} else {
		current = v
	}
	req.Header[userAgent] = append(req.Header[userAgent][:0], current)

	return next.HandleBuild(ctx, in)
}
