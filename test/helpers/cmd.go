// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/test/config"

	"github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"k8s.io/client-go/util/jsonpath"
)

// CmdRes contains a variety of data which results from running a command.
type CmdRes struct {
	cmd      string          // Command to run
	params   []string        // Parameters to provide to command
	stdout   *Buffer         // Stdout from running cmd
	stderr   *Buffer         // Stderr from running cmd
	success  bool            // Whether command successfully executed
	exitcode int             // The exit code of cmd
	duration time.Duration   // Is the representation of the the time that command took to execute.
	wg       *sync.WaitGroup // Used to wait until the command has finished running when used in conjunction with a Context
	err      error           // If the command had any error being executed, the error will be written here.
}

// GetCmd returns res's cmd.
func (res *CmdRes) GetCmd() string {
	return res.cmd
}

// GetExitCode returns res's exitcode.
func (res *CmdRes) GetExitCode() int {
	return res.exitcode
}

// GetStdOut returns the contents of the stdout buffer of res as a string.
func (res *CmdRes) GetStdOut() string {
	return res.stdout.String()
}

// GetStdErr returns the contents of the stderr buffer of res as a string.
func (res *CmdRes) GetStdErr() string {
	return res.stderr.String()
}

// SendToLog writes to `TestLogWriter` the debug message for the running
// command, if the quietMode argument is true will print only the command and
// the exitcode.
func (res *CmdRes) SendToLog(quietMode bool) {
	if quietMode {
		logformat := "cmd: %q exitCode: %d duration: %s\n"
		fmt.Fprintf(&config.TestLogWriter, logformat, res.cmd, res.GetExitCode(), res.duration)
		return
	}

	logformat := "cmd: %q exitCode: %d duration: %s stdout:\n%s\n"
	log := fmt.Sprintf(logformat, res.cmd, res.GetExitCode(), res.duration, res.stdout.String())
	if res.stderr.Len() > 0 {
		log = fmt.Sprintf("%sstderr:\n%s\n", log, res.stderr.String())
	}
	fmt.Fprint(&config.TestLogWriter, log)
}

// WasSuccessful returns true if cmd completed successfully.
func (res *CmdRes) WasSuccessful() bool {
	return res.success
}

// ExpectFail asserts whether res failed to execute. It accepts an optional
// parameter that can be used to annotate failure messages.
func (res *CmdRes) ExpectFail(optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res).ShouldNot(
		CMDSuccess(), optionalDescription...)
}

// ExpectSuccess asserts whether res executed successfully. It accepts an optional
// parameter that can be used to annotate failure messages.
func (res *CmdRes) ExpectSuccess(optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res).Should(
		CMDSuccess(), optionalDescription...)
}

// ExpectContains asserts a string into the stdout of the response of executed
// command. It accepts an optional parameter that can be used to annotate
// failure messages.
func (res *CmdRes) ExpectContains(data string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Output().String()).To(
		gomega.ContainSubstring(data), optionalDescription...)
}

// ExpectDoesNotContain asserts that a string is not contained in the stdout of
// the executed command. It accepts an optional parameter that can be used to
// annotate failure messages.
func (res *CmdRes) ExpectDoesNotContain(data string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Output().String()).ToNot(
		gomega.ContainSubstring(data), optionalDescription...)
}

// ExpectDoesNotMatchRegexp asserts that the stdout of the executed command
// doesn't match the regexp. It accepts an optional parameter that can be used
// to annotate failure messages.
func (res *CmdRes) ExpectDoesNotMatchRegexp(regexp string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Output().String()).ToNot(
		gomega.MatchRegexp(regexp), optionalDescription...)
}

// CountLines return the number of lines in the stdout of res.
func (res *CmdRes) CountLines() int {
	return strings.Count(res.stdout.String(), "\n")
}

// CombineOutput returns the combined output of stdout and stderr for res.
func (res *CmdRes) CombineOutput() *bytes.Buffer {
	result := new(bytes.Buffer)
	result.WriteString(res.stdout.String())
	result.WriteString(res.stderr.String())
	return result
}

// IntOutput returns the stdout of res as an integer
func (res *CmdRes) IntOutput() (int, error) {
	return strconv.Atoi(strings.Trim(res.stdout.String(), "\n\r"))
}

// FindResults filters res's stdout using the provided JSONPath filter. It
// returns an array of the values that match the filter, and an error if
// the unmarshalling of the stdout of res fails.
// TODO - what exactly is the need for this vs. Filter function below?
func (res *CmdRes) FindResults(filter string) ([]reflect.Value, error) {

	var data interface{}
	var result []reflect.Value

	err := json.Unmarshal(res.stdout.Bytes(), &data)
	if err != nil {
		return nil, err
	}
	parser := jsonpath.New("").AllowMissingKeys(true)
	parser.Parse(filter)
	fullResults, _ := parser.FindResults(data)
	for _, res := range fullResults {
		for _, val := range res {
			result = append(result, val)
		}
	}
	return result, nil
}

// Filter returns the contents of res's stdout filtered using the provided
// JSONPath filter in a buffer. Returns an error if the unmarshalling of the
// contents of res's stdout fails.
func (res *CmdRes) Filter(filter string) (*FilterBuffer, error) {
	var data interface{}
	result := new(bytes.Buffer)

	err := json.Unmarshal(res.stdout.Bytes(), &data)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON from command %q",
			res.cmd)
	}
	parser := jsonpath.New("").AllowMissingKeys(true)
	parser.Parse(filter)
	err = parser.Execute(result, data)
	if err != nil {
		return nil, err
	}
	return &FilterBuffer{result}, nil
}

// ByLines returns res's stdout split by the newline character and, if the stdout
// contains `\r\n`, it will be split by carriage return and new line characters.
func (res *CmdRes) ByLines() []string {
	stdoutStr := res.stdout.String()
	sep := "\n"
	if strings.Contains(stdoutStr, "\r\n") {
		sep = "\r\n"
	}
	stdoutStr = strings.TrimRight(stdoutStr, sep)
	return strings.Split(stdoutStr, sep)
}

// KVOutput returns a map of the stdout of res split based on
// the separator '='.
// For example, the following strings would be split as follows:
// 		a=1
// 		b=2
// 		c=3
func (res *CmdRes) KVOutput() map[string]string {
	result := make(map[string]string)
	for _, line := range res.ByLines() {
		vals := strings.Split(line, "=")
		if len(vals) == 2 {
			result[vals[0]] = vals[1]
		}
	}
	return result
}

// Output returns res's stdout.
func (res *CmdRes) Output() *Buffer {
	return res.stdout
}

// OutputPrettyPrint returns a string with the ExitCode, stdout and stderr in a
// pretty format.
func (res *CmdRes) OutputPrettyPrint() string {
	format := func(message string) string {
		result := []string{}
		for _, line := range strings.Split(message, "\n") {
			result = append(result, fmt.Sprintf("\t %s", line))
		}
		return strings.Join(result, "\n")

	}
	return fmt.Sprintf(
		"Exitcode: %d \nStdout:\n %s\nStderr:\n %s\n",
		res.GetExitCode(),
		format(res.GetStdOut()),
		format(res.GetStdErr()))
}

// ExpectEqual asserts whether cmdRes.Output().String() and expected are equal.
// It accepts an optional parameter that can be used to annotate failure
// messages.
func (res *CmdRes) ExpectEqual(expected string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Output().String()).Should(
		gomega.Equal(expected), optionalDescription...)
}

// Reset resets res's stdout buffer to be empty.
func (res *CmdRes) Reset() {
	res.stdout.Reset()
	return
}

// SingleOut returns res's stdout as a string without any newline characters
func (res *CmdRes) SingleOut() string {
	strstdout := res.stdout.String()
	strstdoutSingle := strings.Replace(strstdout, "\n", "", -1)
	return strings.Replace(strstdoutSingle, "\r", "", -1)
}

// Unmarshal unmarshalls res's stdout into data. It assumes that the stdout of
// res is in JSON format. Returns an error if the unmarshalling fails.
func (res *CmdRes) Unmarshal(data interface{}) error {
	err := json.Unmarshal(res.stdout.Bytes(), data)
	return err
}

// GetDebugMessage returns executed command and its output
func (res *CmdRes) GetDebugMessage() string {
	return fmt.Sprintf("cmd: %s\n%s", res.GetCmd(), res.OutputPrettyPrint())
}

// WaitUntilMatch waits until the given substring is present in the `CmdRes.stdout`
// If the timeout is reached it will return an error.
func (res *CmdRes) WaitUntilMatch(substr string) error {
	body := func() bool {
		return strings.Contains(res.Output().String(), substr)
	}

	return WithTimeout(
		body,
		fmt.Sprintf("%s is not in the output after timeout", substr),
		&TimeoutConfig{Timeout: HelperTimeout})
}

// WaitUntilMatchRegexp waits until the `CmdRes.stdout` matches the given regexp.
// If the timeout is reached it will return an error.
func (res *CmdRes) WaitUntilMatchRegexp(expr string) error {
	r := regexp.MustCompile(expr)
	body := func() bool {
		return r.Match(res.Output().Bytes())
	}

	return WithTimeout(
		body,
		fmt.Sprintf("The output doesn't match regexp %q after timeout", expr),
		&TimeoutConfig{Timeout: HelperTimeout})
}

// WaitUntilFinish waits until the command context completes correctly
func (res *CmdRes) WaitUntilFinish() {
	if res.wg == nil {
		return
	}
	res.wg.Wait()
}

// GetErr returns error created from program output if command is not successful
func (res *CmdRes) GetErr(context string) error {
	if res.WasSuccessful() {
		return nil
	}
	return &cmdError{fmt.Sprintf("%s (%s) output: %s", context, res.err, res.GetDebugMessage())}
}

// GetError returns the error for this CmdRes.
func (res *CmdRes) GetError() error {
	return res.err
}

// BeSuccesfulMatcher a new Ginkgo matcher for CmdRes struct
type BeSuccesfulMatcher struct{}

// Match validates that the given interface will be a `*CmdRes` struct and it
// was successful. In case of not a valid CmdRes will return an error. If the
// command was not successful it returns false.
func (matcher *BeSuccesfulMatcher) Match(actual interface{}) (success bool, err error) {
	res, ok := actual.(*CmdRes)
	if !ok {
		return false, fmt.Errorf("%q is not a valid *CmdRes type", actual)
	}
	return res.WasSuccessful(), nil
}

// FailureMessage it returns a pretty printed error message in the case of the
// command was not successful.
func (matcher *BeSuccesfulMatcher) FailureMessage(actual interface{}) (message string) {
	res, _ := actual.(*CmdRes)
	return fmt.Sprintf("Expected command: %s \nTo succeed, but it failed:\n%s",
		res.GetCmd(), res.OutputPrettyPrint())
}

// NegatedFailureMessage returns a pretty printed error message in case of the
// command is tested with a negative
func (matcher *BeSuccesfulMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	res, _ := actual.(*CmdRes)
	return fmt.Sprintf("Expected command: %s\nTo have failed, but it was successful:\n%s",
		res.GetCmd(), res.OutputPrettyPrint())
}

// CMDSuccess return a new Matcher that expects a CmdRes is a successful run command.
func CMDSuccess() types.GomegaMatcher {
	return &BeSuccesfulMatcher{}
}

// cmdError is a implementation of error with String method to improve the debugging.
type cmdError struct {
	s string
}

func (e *cmdError) Error() string {
	return e.s
}

func (e *cmdError) String() string {
	return e.s
}
