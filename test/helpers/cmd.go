// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	"github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"k8s.io/client-go/util/jsonpath"

	"github.com/cilium/cilium/test/logger"
)

// CmdStreamBuffer is a buffer that buffers the stream output of a command.
type CmdStreamBuffer struct {
	*Buffer
	cmd string
}

// Cmd returns the command that generated the stream.
func (b CmdStreamBuffer) Cmd() string {
	return b.cmd
}

// ByLines returns res's stdout split by the newline character and, if the
// stdout contains `\r\n`, it will be split by carriage return and new line
// characters.
func (b *CmdStreamBuffer) ByLines() []string {
	out := b.String()
	sep := "\n"
	if strings.Contains(out, "\r\n") {
		sep = "\r\n"
	}
	out = strings.TrimRight(out, sep)
	return strings.Split(out, sep)
}

// KVOutput returns a map of the stdout of res split based on
// the separator '='.
// For example, the following strings would be split as follows:
//
//	a=1
//	b=2
//	c=3
//	a=1
//	b=2
//	c=3
func (b *CmdStreamBuffer) KVOutput() map[string]string {
	result := make(map[string]string)
	for _, line := range b.ByLines() {
		vals := strings.Split(line, "=")
		if len(vals) == 2 {
			result[vals[0]] = vals[1]
		}
	}
	return result
}

// Filter returns the contents of res's stdout filtered using the provided
// JSONPath filter in a buffer. Returns an error if the unmarshalling of the
// contents of res's stdout fails.
func (b *CmdStreamBuffer) Filter(filter string) (*FilterBuffer, error) {
	var data interface{}
	result := new(bytes.Buffer)

	err := json.Unmarshal(b.Bytes(), &data)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON from command %q\n%w\n%s", b.Cmd(), err, b.Bytes())
	}
	parser := jsonpath.New("").AllowMissingKeys(true)
	parser.Parse(filter)
	err = parser.Execute(result, data)
	if err != nil {
		return nil, err
	}
	return &FilterBuffer{result}, nil
}

// FilterLinesJSONPath decodes each line as JSON and applies the JSONPath
// filter to each line. Returns an array with the result for each line.
func (b *CmdStreamBuffer) FilterLinesJSONPath(filter *jsonpath.JSONPath) ([]FilterBuffer, error) {
	lines := b.ByLines()
	results := make([]FilterBuffer, 0, len(lines))
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}

		var data interface{}
		result := new(bytes.Buffer)
		err := json.Unmarshal([]byte(line), &data)
		if err != nil {
			return nil, fmt.Errorf("could not parse %q as JSON (line %d of %q)", line, i, b.Cmd())
		}

		err = filter.Execute(result, data)
		if err != nil {
			return nil, err
		}
		results = append(results, FilterBuffer{result})
	}
	return results, nil
}

// FilterLines works like Filter, but applies the JSONPath filter to each line
// separately and returns returns a Buffer for each line. An error is
// returned only for the first line which cannot be unmarshalled.
func (b *CmdStreamBuffer) FilterLines(filter string) ([]FilterBuffer, error) {
	parsedFilter := jsonpath.New("").AllowMissingKeys(true)
	err := parsedFilter.Parse(filter)
	if err != nil {
		return nil, err
	}
	return b.FilterLinesJSONPath(parsedFilter)
}

// CmdRes contains a variety of data which results from running a command.
type CmdRes struct {
	cmd      string          // Command to run
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

// GetStdOut returns res's stdout.
func (res *CmdRes) GetStdOut() *CmdStreamBuffer {
	return &CmdStreamBuffer{
		res.stdout,
		res.cmd,
	}
}

// GetStdErr returns res's stderr.
func (res *CmdRes) GetStdErr() *CmdStreamBuffer {
	return &CmdStreamBuffer{
		res.stderr,
		res.cmd,
	}
}

// Stdout returns the contents of the stdout buffer of res as a string.
func (res *CmdRes) Stdout() string {
	return res.GetStdOut().String()
}

// Stderr returns the contents of the stderr buffer of res as a string.
func (res *CmdRes) Stderr() string {
	return res.GetStdErr().String()
}

// SendToLog writes to `TestLogWriter` the debug message for the running
// command, if the quietMode argument is true will print only the command and
// the exitcode.
func (res *CmdRes) SendToLog(quietMode bool) {
	if quietMode {
		logformat := "cmd: %q exitCode: %d duration: %s\n"
		fmt.Fprintf(&logger.TestLogWriter, logformat, res.cmd, res.GetExitCode(), res.duration)
		return
	}

	logformat := "cmd: %q exitCode: %d duration: %s stdout:\n%s\n"
	log := fmt.Sprintf(logformat, res.cmd, res.GetExitCode(), res.duration, res.stdout.String())
	if res.err != nil {
		log = fmt.Sprintf("%serr:\n%s\n", log, res.err)
	}
	if res.stderr.Len() > 0 {
		log = fmt.Sprintf("%sstderr:\n%s\n", log, res.stderr.String())
	}
	fmt.Fprint(&logger.TestLogWriter, log)
}

// WasSuccessful returns true if cmd completed successfully.
func (res *CmdRes) WasSuccessful() bool {
	return res.err == nil && res.success
}

// ExpectFail asserts whether res failed to execute. It accepts an optional
// parameter that can be used to annotate failure messages.
func (res *CmdRes) ExpectFail(optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res).ShouldNot(
		CMDSuccess(), optionalDescription...)
}

// ExpectFailWithError asserts whether res failed to execute with the
// error output containing the given data.  It accepts an optional
// parameter that can be used to annotate failure messages.
func (res *CmdRes) ExpectFailWithError(data string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res).ShouldNot(
		CMDSuccess(), optionalDescription...) &&
		gomega.ExpectWithOffset(1, res.Stderr()).To(
			gomega.ContainSubstring(data), optionalDescription...)
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
	return gomega.ExpectWithOffset(1, res.Stdout()).To(
		gomega.ContainSubstring(data), optionalDescription...)
}

// ExpectMatchesRegexp asserts that the stdout of the executed command
// matches the regexp. It accepts an optional parameter that can be
// used to annotate failure messages.
func (res *CmdRes) ExpectMatchesRegexp(regexp string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Stdout()).To(
		gomega.MatchRegexp(regexp), optionalDescription...)
}

// ExpectContainsFilterLine applies the provided JSONPath filter to each line
// of stdout of the executed command and asserts that the expected string
// matches at least one of the lines.
// It accepts an optional parameter that can be used to annotate failure
// messages.
func (res *CmdRes) ExpectContainsFilterLine(filter, expected string, optionalDescription ...interface{}) bool {
	lines, err := res.FilterLines(filter)
	gomega.ExpectWithOffset(1, err).To(gomega.BeNil(), optionalDescription...)
	sLines := []string{}
	for _, fLine := range lines {
		sLines = append(sLines, fLine.ByLines()...)
	}
	return gomega.ExpectWithOffset(1, sLines).To(
		gomega.ContainElement(expected), optionalDescription...)
}

// ExpectDoesNotContain asserts that a string is not contained in the stdout of
// the executed command. It accepts an optional parameter that can be used to
// annotate failure messages.
func (res *CmdRes) ExpectDoesNotContain(data string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Stdout()).ToNot(
		gomega.ContainSubstring(data), optionalDescription...)
}

// ExpectDoesNotMatchRegexp asserts that the stdout of the executed command
// doesn't match the regexp. It accepts an optional parameter that can be used
// to annotate failure messages.
func (res *CmdRes) ExpectDoesNotMatchRegexp(regexp string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Stdout()).ToNot(
		gomega.MatchRegexp(regexp), optionalDescription...)
}

// ExpectDoesNotContainFilterLine applies the provided JSONPath filter to each
// line of stdout of the executed command and asserts that the expected string
// does not matches any of the lines.
// It accepts an optional parameter that can be used to annotate failure
// messages.
func (res *CmdRes) ExpectDoesNotContainFilterLine(filter, expected string, optionalDescription ...interface{}) bool {
	lines, err := res.FilterLines(filter)
	gomega.ExpectWithOffset(1, err).To(gomega.BeNil(), optionalDescription...)
	sLines := []string{}
	for _, fLine := range lines {
		sLines = append(sLines, fLine.ByLines()...)
	}
	return gomega.ExpectWithOffset(1, sLines).ToNot(
		gomega.ContainElement(expected), optionalDescription...)
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
	return strconv.Atoi(strings.TrimSpace(res.stdout.String()))
}

// FloatOutput returns the stdout of res as a float
func (res *CmdRes) FloatOutput() (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(res.stdout.String()), 64)
}

// InRange returns nil if res matches the expected value range or error otherwise
func (res *CmdRes) InRange(min, max int) error {
	raw, err := res.FloatOutput()
	if err != nil {
		return err
	}
	val := int(raw)
	if val >= min && val <= max {
		return nil
	} else {
		return fmt.Errorf(
			"Expected result %d (%s) is not in the range of [%d, %d]",
			val, strings.TrimSpace(res.stdout.String()), min, max)
	}
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
		result = append(result, res...)
	}
	return result, nil
}

// Filter returns the contents of res's stdout filtered using the provided
// JSONPath filter in a buffer. Returns an error if the unmarshalling of the
// contents of res's stdout fails.
func (res *CmdRes) Filter(filter string) (*FilterBuffer, error) {
	return res.GetStdOut().Filter(filter)
}

// FilterLinesJSONPath decodes each line as JSON and applies the JSONPath
// filter to each line. Returns an array with the result for each line.
func (res *CmdRes) FilterLinesJSONPath(filter *jsonpath.JSONPath) ([]FilterBuffer, error) {
	return res.GetStdOut().FilterLinesJSONPath(filter)
}

// FilterLines works like Filter, but applies the JSONPath filter to each line
// separately and returns returns a buffer for each line. An error is
// returned only for the first line which cannot be unmarshalled.
func (res *CmdRes) FilterLines(filter string) ([]FilterBuffer, error) {
	return res.GetStdOut().FilterLines(filter)
}

// ByLines returns res's stdout split by the newline character and, if the
// stdout contains `\r\n`, it will be split by carriage return and new line
// characters.
func (res *CmdRes) ByLines() []string {
	return res.GetStdOut().ByLines()
}

// KVOutput returns a map of the stdout of res split based on
// the separator '='.
// For example, the following strings would be split as follows:
//
//	a=1
//	b=2
//	c=3
func (res *CmdRes) KVOutput() map[string]string {
	return res.GetStdOut().KVOutput()
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
	errStr := ""
	if res.err != nil {
		errStr = fmt.Sprintf("Err: %s\n", res.err)
	}
	return fmt.Sprintf(
		"Exitcode: %d \n%sStdout:\n %s\nStderr:\n %s\n",
		res.GetExitCode(),
		errStr,
		format(res.Stdout()),
		format(res.Stderr()))
}

// ExpectEqual asserts whether cmdRes.Output().String() and expected are equal.
// It accepts an optional parameter that can be used to annotate failure
// messages.
func (res *CmdRes) ExpectEqual(expected string, optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.Stdout()).Should(
		gomega.Equal(expected), optionalDescription...)
}

// Reset resets res's stdout buffer to be empty.
func (res *CmdRes) Reset() {
	res.stdout.Reset()
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
	return json.Unmarshal(res.stdout.Bytes(), data)
}

// GetDebugMessage returns executed command and its output
func (res *CmdRes) GetDebugMessage() string {
	return fmt.Sprintf("cmd: %s\n%s", res.GetCmd(), res.OutputPrettyPrint())
}

// WaitUntilMatch waits until the given substring is present in the `CmdRes.stdout`
// If the timeout is reached it will return an error.
func (res *CmdRes) WaitUntilMatch(substr string) error {
	return res.WaitUntilMatchTimeout(substr, HelperTimeout)
}

// WaitUntilMatchTimeout is the same as WaitUntilMatch but with a user-provided
// timeout value.
func (res *CmdRes) WaitUntilMatchTimeout(substr string, timeout time.Duration) error {
	body := func() bool {
		return strings.Contains(res.OutputPrettyPrint(), substr)
	}

	return WithTimeout(
		body,
		fmt.Sprintf("%s is not in the output after timeout", substr),
		&TimeoutConfig{Timeout: timeout})
}

// WaitUntilMatchRegexp waits until the `CmdRes.stdout` matches the given regexp.
// If the timeout is reached it will return an error.
func (res *CmdRes) WaitUntilMatchRegexp(expr string, timeout time.Duration) error {
	r := regexp.MustCompile(expr)
	body := func() bool {
		return r.Match(res.GetStdOut().Bytes())
	}

	return WithTimeout(
		body,
		fmt.Sprintf("The output doesn't match regexp %q after timeout", expr),
		&TimeoutConfig{Timeout: timeout})
}

// WaitUntilMatchFilterLineTimeout applies the JSONPath 'filter' to each line of
// `CmdRes.stdout` and waits until a line matches the 'expected' output.
// If the 'timeout' is reached it will return an error.
func (res *CmdRes) WaitUntilMatchFilterLineTimeout(filter, expected string, timeout time.Duration) error {
	parsedFilter := jsonpath.New("").AllowMissingKeys(true)
	err := parsedFilter.Parse(filter)
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	body := func() bool {
		lines, err := res.FilterLinesJSONPath(parsedFilter)
		if err != nil {
			errChan <- err
			return true
		}
		for _, line := range lines {
			if line.String() == expected {
				return true
			}
		}

		return false
	}

	err = RepeatUntilTrue(body, &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return fmt.Errorf(
			"Expected string %q is not in the filter output of %q: %s",
			expected, filter, err)
	}

	select {
	case err := <-errChan:
		return err
	default:
	}

	return nil
}

// WaitUntilMatchFilterLine applies the JSONPath 'filter' to each line of
// `CmdRes.stdout` and waits until a line matches the 'expected' output.
// If helpers.HelperTimout is reached it will return an error.
func (res *CmdRes) WaitUntilMatchFilterLine(filter, expected string) error {
	return res.WaitUntilMatchFilterLineTimeout(filter, expected, HelperTimeout)
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
