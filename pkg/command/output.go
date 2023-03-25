// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package command

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/jsonpath"
)

var (
	outputOpt string
	re        = regexp.MustCompile(`^jsonpath\=(.*)`)
)

// OutputOption returns true if an output option was specified.
func OutputOption() bool {
	return len(outputOpt) > 0
}

// OutputOptionString returns the output option as a string
func OutputOptionString() string {
	if outputOpt == "yaml" {
		return "YAML"
	}

	if outputOpt == "json" || re.MatchString(outputOpt) {
		return "JSON"
	}

	return "unknown"
}

// AddOutputOption adds the -o|--output option to any cmd to export to json or yaml.
func AddOutputOption(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&outputOpt, "output", "o", "", "json| yaml| jsonpath='{}'")
}

// ForceJSON sets output mode to JSON (for unit tests)
func ForceJSON() {
	outputOpt = "json"
}

// PrintOutput receives an interface and dump the data using the --output flag.
// ATM only json or jsonpath. In the future yaml
func PrintOutput(data interface{}) error {
	return PrintOutputWithType(data, outputOpt)
}

// PrintOutputWithPatch merges data with patch and dump the data using the --output flag.
func PrintOutputWithPatch(data interface{}, patch interface{}) error {
	mergedInterface, err := mergeInterfaces(data, patch)
	if err != nil {
		return fmt.Errorf("Unable to merge Interfaces:%v", err)
	}
	return PrintOutputWithType(mergedInterface, outputOpt)
}

func mergeInterfaces(data, patch interface{}) (interface{}, error) {
	var i1, i2 interface{}

	data1, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	data2, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data1, &i1)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data2, &i2)
	if err != nil {
		return nil, err
	}
	return recursiveMerge(i1, i2), nil
}

func recursiveMerge(i1, i2 interface{}) interface{} {
	switch i1 := i1.(type) {
	case map[string]interface{}:
		i2, ok := i2.(map[string]interface{})
		if !ok {
			return i1
		}
		for k, v2 := range i2 {
			if v1, ok := i1[k]; ok {
				i1[k] = recursiveMerge(v1, v2)
			} else {
				i1[k] = v2
			}
		}
	case nil:
		i2, ok := i2.(map[string]interface{})
		if ok {
			return i2
		}
	}
	return i1
}

// PrintOutputWithType receives an interface and dump the data using the --output flag.
// ATM only json, yaml, or jsonpath.
func PrintOutputWithType(data interface{}, outputType string) error {
	if outputType == "json" {
		return dumpJSON(data, "")
	}

	if outputType == "yaml" {
		return dumpYAML(data)
	}

	if re.MatchString(outputType) {
		return dumpJSON(data, re.ReplaceAllString(outputType, "$1"))
	}

	return fmt.Errorf("couldn't find output printer")
}

// DumpJSONToString dumps the contents of data into a string. If jsonpath is
// non-empty, will attempt to do jsonpath filtering using said string. Returns a
// string containing the JSON in data, or an error if any JSON marshaling,
// parsing operations fail.
func DumpJSONToString(data interface{}, jsonPath string) (string, error) {
	if len(jsonPath) == 0 {
		result, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't marshal to json: '%s'\n", err)
			return "", err
		}
		fmt.Println(string(result))
		return "", nil
	}

	parser := jsonpath.New("").AllowMissingKeys(true)
	if err := parser.Parse(jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't parse jsonpath expression: '%s'\n", err)
		return "", err
	}

	var sb strings.Builder
	if err := parser.Execute(&sb, data); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't parse jsonpath expression: '%s'\n", err)
		return "", err

	}
	return sb.String(), nil
}

// dumpJSON dumps the data variable to the stdout as json.
// If something fails, it returns an error
// If jsonPath is passed, it runs the json query over data var.
func dumpJSON(data interface{}, jsonPath string) error {
	jsonStr, err := DumpJSONToString(data, jsonPath)
	if err != nil {
		return err
	}
	fmt.Println(jsonStr)
	return nil
}

// dumpYAML dumps the data variable to the stdout as yaml.
// If something fails, it returns an error
func dumpYAML(data interface{}) error {
	result, err := yaml.Marshal(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't marshal to yaml: '%s'\n", err)
		return err
	}
	fmt.Println(string(result))
	return nil
}
