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

	"github.com/onsi/gomega"
	"k8s.io/client-go/util/jsonpath"
)

// CmdRes contains the result from running a command.
type CmdRes struct {
	cmd    string        // Command to run
	params []string      // Parameters to provide to command
	stdout *bytes.Buffer // Stdout from running cmd
	stderr *bytes.Buffer // Stderr from running cmd
	exit   bool          // Whether command successfully ran.
}

// GetCmd returns res's cmd.
func (res *CmdRes) GetCmd() string {
	return res.cmd
}

// GetStdOut returns the contents of the stdout buffer of res as a string.
func (res *CmdRes) GetStdOut() string {
	return res.stdout.String()
}

// GetStdErr returns the contents of the stderr buffer of res as a string.
func (res *CmdRes) GetStdErr() string {
	return res.stderr.String()
}

// WasSuccessful returns true if cmd completed successfully.
func (res *CmdRes) WasSuccessful() bool {
	return res.exit
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

//CountLines return the number of lines in the stdout of res.
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

// FindResults filter CmdRes using jsonpath and returns an interface with the values
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

//Filter filters cmdRes using the provided JSONPath filter.
func (res *CmdRes) Filter(filter string) (*bytes.Buffer, error) {
	var data interface{}
	result := new(bytes.Buffer)

	err := json.Unmarshal(res.stdout.Bytes(), &data)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON")
	}
	parser := jsonpath.New("").AllowMissingKeys(true)
	parser.Parse(filter)
	err = parser.Execute(result, data)
	if err != nil {
		return nil, err
	}
	return result, nil
}

//ByLines return an array with all stdout lines
func (res *CmdRes) ByLines() []string {
	return strings.Split(res.stdout.String(), "\n")
}

// KVOutput returns a map of the stdout of the provided CmdRes split based on
// the separator '='.
// This is going to be used when the output will be like this:
// 		a=1
// 		b=2
// 		c=3
// This funtion will return a map with the values in the stdout output
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

// Output returns the contents of res's stdout.
func (res *CmdRes) Output() *bytes.Buffer {
	return res.stdout
}

// Reset stdout bytes with an empty buffer
func (res *CmdRes) Reset() {
	res.stdout.Reset()
	return
}

// SingleOut returns the stdout of res without any newline characters
func (res *CmdRes) SingleOut() string {
	return strings.Replace(res.stdout.String(), "\n", "", -1)
}

// Unmarshal unmarshals res's stdout into data
func (res *CmdRes) Unmarshal(data interface{}) error {
	err := json.Unmarshal(res.stdout.Bytes(), &data)
	return err
}
