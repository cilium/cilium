// Copyright 2016-2018 Authors of Cilium
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

package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/spf13/cobra"
	"k8s.io/client-go/util/jsonpath"
)

var (
	outputOpt string
	re        = regexp.MustCompile(`^jsonpath\=(.*)`)
)

// OutputJSON returns true if the JSON output option was specified
func OutputJSON() bool {
	return len(outputOpt) > 0
}

//AddJSONOutput adds the -o|--output option to any cmd to export to json
func AddJSONOutput(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&outputOpt, "output", "o", "", "json| jsonpath='{}'")
}

//PrintOutput receives an interface and dump the data using the --output flag.
//ATM only json or jsonpath. In the future yaml
func PrintOutput(data interface{}) error {
	return PrintOutputWithType(data, outputOpt)
}

//PrintOutputWithType receives an interface and dump the data using the --output flag.
//ATM only json or jsonpath. In the future yaml
func PrintOutputWithType(data interface{}, outputType string) error {
	if outputType == "json" {
		return dumpJSON(data, "")
	}

	if re.MatchString(outputType) {
		return dumpJSON(data, re.ReplaceAllString(outputType, "$1"))
	}

	return fmt.Errorf("couldn't found output printer")
}

// DumpJSONToSlice dumps the contents of data into a byte slice. If jsonpath
// is non-empty, will attempt to do jsonpath filtering using said string.
// Returns byte array containing the JSON in data, or an error if any JSON
// marshaling, parsing operations fail.
func DumpJSONToSlice(data interface{}, jsonPath string) ([]byte, error) {
	if len(jsonPath) == 0 {
		result, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't marshal to json: '%s'\n", err)
			return nil, err
		}
		fmt.Println(string(result))
		return nil, nil
	}

	parser := jsonpath.New("").AllowMissingKeys(true)
	if err := parser.Parse(jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't parse jsonpath expression: '%s'\n", err)
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := parser.Execute(buf, data); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't parse jsonpath expression: '%s'\n", err)
		return nil, err

	}
	return buf.Bytes(), nil
}

// dumpJSON dump the data variable to the stdout as json.
// If somethings fail, it'll return an error
// If jsonPath is passed, it'll run the json query over data var.
func dumpJSON(data interface{}, jsonPath string) error {
	jsonBytes, err := DumpJSONToSlice(data, jsonPath)
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes[:]))
	return nil
}
