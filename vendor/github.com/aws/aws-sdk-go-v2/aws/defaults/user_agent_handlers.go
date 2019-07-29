package defaults

import (
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// SDKVersionUserAgentHandler is a request handler for adding the SDK Version
// to the user agent.
var SDKVersionUserAgentHandler = aws.NamedHandler{
	Name: "core.SDKVersionUserAgentHandler",
	Fn: aws.MakeAddToUserAgentHandler(aws.SDKName, aws.SDKVersion,
		runtime.Version(), runtime.GOOS, runtime.GOARCH),
}

const execEnvVar = `AWS_EXECUTION_ENV`
const execEnvUAKey = `exec-env`

// AddHostExecEnvUserAgentHander is a request handler appending the SDK's
// execution environment to the user agent.
//
// If the environment variable AWS_EXECUTION_ENV is set, its value will be
// appended to the user agent string.
var AddHostExecEnvUserAgentHander = aws.NamedHandler{
	Name: "core.AddHostExecEnvUserAgentHander",
	Fn: func(r *aws.Request) {
		v := os.Getenv(execEnvVar)
		if len(v) == 0 {
			return
		}

		aws.AddToUserAgent(r, execEnvUAKey+"/"+v)
	},
}
