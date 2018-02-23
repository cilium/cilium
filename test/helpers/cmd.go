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
	"strconv"
	"strings"

	"github.com/cilium/cilium/test/config"

	"github.com/onsi/gomega"
	"k8s.io/client-go/util/jsonpath"
)

// CmdRes contains a variety of data which results from running a command.
type CmdRes struct {
	cmd      string        // Command to run
	params   []string      // Parameters to provide to command
	stdout   *bytes.Buffer // Stdout from running cmd
	stderr   *bytes.Buffer // Stderr from running cmd
	success  bool          // Whether command successfully executed
	exitcode int           // The exit code of cmd
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

// SendToLog writes to `TestLogWriter` the debug message for the running command
func (res *CmdRes) SendToLog() {
	fmt.Fprintf(&config.TestLogWriter, "cmd: %q exitCode: %d \n %s\n",
		res.cmd,
		res.GetExitCode(),
		res.CombineOutput())
}

// WasSuccessful returns true if cmd completed successfully.
func (res *CmdRes) WasSuccessful() bool {
	return res.success
}

// ExpectFail asserts whether res failed to execute. It accepts an optional
// parameter that can be used to annotate failure messages.
func (res *CmdRes) ExpectFail(optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.WasSuccessful()).Should(
		gomega.BeFalse(), optionalDescription...)
}

// ExpectSuccess asserts whether res executed successfully. It accepts an optional
// parameter that can be used to annotate failure messages.
func (res *CmdRes) ExpectSuccess(optionalDescription ...interface{}) bool {
	return gomega.ExpectWithOffset(1, res.WasSuccessful()).Should(
		gomega.BeTrue(), optionalDescription...)
}

// CountLines return the number of lines in the stdout of res.
func (res *CmdRes) CountLines() int {
	return strings.Count(res.stdout.String(), "\n")
}

// CombineOutput returns the combined output of stdout and stderr for res.
func (res *CmdRes) CombineOutput() *bytes.Buffer {
	result := res.stdout
	result.WriteString(res.stderr.String())
	return result
}

// IntOutput returns the stdout of res as an integer
func (res *CmdRes) IntOutput() (int, error) {
	return strconv.Atoi(strings.Trim(res.stdout.String(), "\n"))
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
func (res *CmdRes) Filter(filter string) (*bytes.Buffer, error) {
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
	return result, nil
}

// ByLines returns res's stdout split by the newline character .
func (res *CmdRes) ByLines() []string {
	return strings.Split(res.stdout.String(), "\n")
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
func (res *CmdRes) Output() *bytes.Buffer {
	return res.stdout
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
	return strings.Replace(res.stdout.String(), "\n", "", -1)
}

// Unmarshal unmarshalls res's stdout into data. It assumes that the stdout of
// res is in JSON format. Returns an error if the unmarshalling fails.
func (res *CmdRes) Unmarshal(data interface{}) error {
	err := json.Unmarshal(res.stdout.Bytes(), &data)
	return err
}

// GetDebugMessage returns executed command and its output
func (res *CmdRes) GetDebugMessage() string {
	return fmt.Sprintf("cmd: %s\noutput: %s", res.GetCmd(), res.CombineOutput())
}
