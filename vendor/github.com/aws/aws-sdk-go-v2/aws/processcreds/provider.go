/*
Package processcreds is a credential Provider to retrieve `credential_process`
credentials.

WARNING: The following describes a method of sourcing credentials from an external
process. This can potentially be dangerous, so proceed with caution. Other
credential providers should be preferred if at all possible. If using this
option, you should make sure that the config file is as locked down as possible
using security best practices for your operating system.

You can use credentials from a `credential_process` in a variety of ways.

One way is to setup your shared config file, located in the default
location, with the `credential_process` key and the command you want to be
called. You also need to set the AWS_SDK_LOAD_CONFIG environment variable
(e.g., `export AWS_SDK_LOAD_CONFIG=1`) to use the shared config file.

    [default]
    credential_process = /command/to/call

Loading configuration using external will use the credential process to retrieve credentials.
NOTE: If there are credentials in the profile you are using, the credential
process will not be used.

    // Initialize a session to load credentials.
	cfg, _ := external.LoadDefaultAWSConfig()

    // Create S3 service client to use the credentials.
    svc := s3.New(cfg)

Another way to use the `credential_process` method is by using
`credentials.NewProvider()` and providing a command to be executed to
retrieve credentials:

    // Create credentials using the Provider.
	cfg := aws.Config{
		Credentials: processcreds.NewProvider("/path/to/command")
	}

    // Create service client value configured for credentials.
    svc := s3.New(cfg)

You can set a non-default timeout for the `credential_process` with another
constructor, `credentials.NewProviderTimeout()`, providing the timeout. To
set a one minute timeout:

    // Create credentials using the Provider.
    provider := processcreds.NewProviderTimeout(
        "/path/to/command",
        time.Duration(500) * time.Millisecond)

If you need more control, you can set any configurable options in the
credentials using one or more option functions. For example, you can set a two
minute timeout, a credential duration of 60 minutes, and a maximum stdout
buffer size of 2k.

    provider := processcreds.NewProvider(
        "/path/to/command",
        func(opt *Provider) {
            opt.Timeout = time.Duration(2) * time.Minute
        })

You can also use your own `exec.Cmd`:

	// Create an exec.Cmd
	myCommand := exec.Command("/path/to/command")

	// Create credentials using your exec.Cmd and custom timeout
	provider := processcreds.NewProviderCommand(
		myCommand,
		func(opt *processcreds.Provider) {
			opt.Timeout = time.Duration(1) * time.Second
		})
*/
package processcreds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/internal/sdkio"
)

const (
	// ProviderName is the name this credentials provider will label any
	// returned credentials Value with.
	ProviderName = `ProcessProvider`

	// ErrCodeProcessProviderParse error parsing process output
	ErrCodeProcessProviderParse = "ProcessProviderParseError"

	// ErrCodeProcessProviderVersion version error in output
	ErrCodeProcessProviderVersion = "ProcessProviderVersionError"

	// ErrCodeProcessProviderRequired required attribute missing in output
	ErrCodeProcessProviderRequired = "ProcessProviderRequiredError"

	// ErrCodeProcessProviderExecution execution of command failed
	ErrCodeProcessProviderExecution = "ProcessProviderExecutionError"

	// errMsgProcessProviderTimeout process took longer than allowed
	errMsgProcessProviderTimeout = "credential process timed out"

	// errMsgProcessProviderProcess process error
	errMsgProcessProviderProcess = "error in credential_process"

	// errMsgProcessProviderParse problem parsing output
	errMsgProcessProviderParse = "parse failed of credential_process output"

	// errMsgProcessProviderVersion version error in output
	errMsgProcessProviderVersion = "wrong version in process output (not 1)"

	// errMsgProcessProviderMissKey missing access key id in output
	errMsgProcessProviderMissKey = "missing AccessKeyId in process output"

	// errMsgProcessProviderMissSecret missing secret acess key in output
	errMsgProcessProviderMissSecret = "missing SecretAccessKey in process output"

	// errMsgProcessProviderPrepareCmd prepare of command failed
	errMsgProcessProviderPrepareCmd = "failed to prepare command"

	// errMsgProcessProviderEmptyCmd command must not be empty
	errMsgProcessProviderEmptyCmd = "command must not be empty"

	// DefaultTimeout default limit on time a process can run.
	DefaultTimeout = time.Duration(1) * time.Minute
)

// Provider satisfies the credentials.Provider interface, and is a
// client to retrieve credentials from a process.
type Provider struct {
	aws.SafeCredentialsProvider

	// A string representing an os command that should return a JSON with
	// credential information.
	command *exec.Cmd

	originalCommand []string

	options ProviderOptions
}

// ProviderOptions is the configuration options for the processcreds Provider
type ProviderOptions struct {
	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration

	// Timeout limits the time a process can run.
	Timeout time.Duration
}

// NewProvider returns a pointer to a new Credentials object wrapping the
// Provider. The credentials will expire every 15 minutes by default.
func NewProvider(command string, options ...func(*ProviderOptions)) *Provider {
	return NewProviderCommand(exec.Command(command), options...)
}

// NewProviderCommand returns a pointer to a new Credentials object with
// the specified command, and default timeout, duration and max buffer size.
func NewProviderCommand(command *exec.Cmd, options ...func(*ProviderOptions)) *Provider {
	p := &Provider{
		command: command,
		options: ProviderOptions{
			Timeout: DefaultTimeout,
		},
	}

	p.RetrieveFn = p.retrieveFn

	for _, option := range options {
		option(&p.options)
	}

	return p
}

type credentialProcessResponse struct {
	Version         int
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string
	SessionToken    string
	Expiration      *time.Time
}

// retrieveFn executes the 'credential_process' and returns the credentials.
func (p *Provider) retrieveFn() (aws.Credentials, error) {
	out, err := p.executeCredentialProcess()
	if err != nil {
		return aws.Credentials{Source: ProviderName}, err
	}

	// Serialize and validate response
	resp := &credentialProcessResponse{}
	if err = json.Unmarshal(out, resp); err != nil {
		return aws.Credentials{Source: ProviderName}, awserr.New(
			ErrCodeProcessProviderParse,
			fmt.Sprintf("%s: %s", errMsgProcessProviderParse, string(out)),
			err)
	}

	if resp.Version != 1 {
		return aws.Credentials{Source: ProviderName}, awserr.New(
			ErrCodeProcessProviderVersion,
			errMsgProcessProviderVersion,
			nil)
	}

	if len(resp.AccessKeyID) == 0 {
		return aws.Credentials{Source: ProviderName}, awserr.New(
			ErrCodeProcessProviderRequired,
			errMsgProcessProviderMissKey,
			nil)
	}

	if len(resp.SecretAccessKey) == 0 {
		return aws.Credentials{Source: ProviderName}, awserr.New(
			ErrCodeProcessProviderRequired,
			errMsgProcessProviderMissSecret,
			nil)
	}

	creds := aws.Credentials{
		Source:          ProviderName,
		AccessKeyID:     resp.AccessKeyID,
		SecretAccessKey: resp.SecretAccessKey,
		SessionToken:    resp.SessionToken,
	}

	// Handle expiration
	if resp.Expiration != nil {
		creds.CanExpire = true
		creds.Expires = (*resp.Expiration).Add(-p.options.ExpiryWindow)
	}

	return creds, nil
}

// prepareCommand prepares the command to be executed.
func (p *Provider) prepareCommand() (context.Context, context.CancelFunc, error) {

	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"cmd.exe", "/C"}
	} else {
		cmdArgs = []string{"sh", "-c"}
	}

	if len(p.originalCommand) == 0 {
		p.originalCommand = make([]string, len(p.command.Args))
		copy(p.originalCommand, p.command.Args)

		// check for empty command because it succeeds
		if len(strings.TrimSpace(p.originalCommand[0])) < 1 {
			return nil, nil, awserr.New(
				ErrCodeProcessProviderExecution,
				fmt.Sprintf(
					"%s: %s",
					errMsgProcessProviderPrepareCmd,
					errMsgProcessProviderEmptyCmd),
				nil)
		}
	}

	timeoutCtx, cancelFunc := context.WithTimeout(context.Background(), p.options.Timeout)

	cmdArgs = append(cmdArgs, p.originalCommand...)
	p.command = exec.CommandContext(timeoutCtx, cmdArgs[0], cmdArgs[1:]...)
	p.command.Env = os.Environ()

	return timeoutCtx, cancelFunc, nil
}

// executeCredentialProcess starts the credential process on the OS and
// returns the results or an error.
func (p *Provider) executeCredentialProcess() ([]byte, error) {
	ctx, cancelFunc, err := p.prepareCommand()
	if err != nil {
		return nil, err
	}
	defer cancelFunc()

	output := bytes.NewBuffer(make([]byte, 0, int(8*sdkio.KibiByte)))

	p.command.Stderr = os.Stderr // display stderr on console for MFA
	p.command.Stdout = output    // get creds json on process's stdout
	p.command.Stdin = os.Stdin   // enable stdin for MFA

	execCh := make(chan error, 1)
	go executeCommand(p.command, execCh)

	select {
	case execError := <-execCh:
		if execError == nil {
			break
		}
		select {
		case <-ctx.Done():
			return output.Bytes(), awserr.New(ErrCodeProcessProviderExecution, errMsgProcessProviderTimeout, execError)
		default:
			return output.Bytes(), awserr.New(ErrCodeProcessProviderExecution, errMsgProcessProviderProcess, execError)
		}
	}

	out := output.Bytes()

	if runtime.GOOS == "windows" {
		// windows adds slashes to quotes
		out = []byte(strings.Replace(string(out), `\"`, `"`, -1))
	}

	return out, nil
}

func executeCommand(cmd *exec.Cmd, exec chan error) {
	// Start the command
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}

	exec <- err
}
