// Copyright 2016-2017 Authors of Cilium
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

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/spf13/cobra"
	"k8s.io/client-go/util/jsonpath"
)

// Fatalf prints the Printf formatted message to stderr and exits the program
// Note: os.Exit(1) is not recoverable
func Fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(msg, args...))
	os.Exit(1)
}

// Usagef prints the Printf formatted message to stderr, prints usage help and
// exits the program
// Note: os.Exit(1) is not recoverable
func Usagef(cmd *cobra.Command, msg string, args ...interface{}) {
	txt := fmt.Sprintf(msg, args...)
	fmt.Fprintf(os.Stderr, "Error: %s\n\n", txt)
	cmd.Help()
	os.Exit(1)
}

func requireEndpointID(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Usagef(cmd, "Missing endpoint id argument")
	}

	if id := policy.ReservedIdentities[args[0]]; id == policy.IdentityUnknown {
		_, _, err := endpoint.ValidateID(args[0])

		if err != nil {
			Fatalf("Cannot parse endpoint id \"%s\": %s", args[0], err)
		}
	}
}

func requireEndpointIDorGlobal(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Usagef(cmd, "Missing endpoint id or 'global' argument")
	}

	if args[0] != "global" {
		requireEndpointID(cmd, args)
	}
}

func requirePath(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Usagef(cmd, "Missing path argument")
	}

	if args[0] == "" {
		Usagef(cmd, "Empty path argument")
	}
}

func requireServiceID(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Usagef(cmd, "Missing service id argument")
	}

	if args[0] == "" {
		Usagef(cmd, "Empty service id argument")
	}
}

var dumpOutput string

//AddMultipleOutput adds the -o|--output option to any cmd to export to json
func AddMultipleOutput(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&dumpOutput, "output", "o", "", "json| jsonpath='{}'")
}

//OutputPrinter receives an interface and dump the data using the --output flag.
//ATM only json or jsonpath. In the future yaml
func OutputPrinter(data interface{}) error {
	var re = regexp.MustCompile(`^jsonpath\=(.*)`)

	if dumpOutput == "json" {
		return dumpJSON(data, "")
	}

	if re.MatchString(dumpOutput) {
		return dumpJSON(data, re.ReplaceAllString(dumpOutput, "$1"))
	}

	return fmt.Errorf("Couldn't found output printer")
}

// dumpJSON dump the data variable to the stdout as json.
// If somethings fail, it'll return an error
// If jsonPath is passed, it'll run the json query over data var.
func dumpJSON(data interface{}, jsonPath string) error {

	if len(jsonPath) == 0 {
		result, err := json.Marshal(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't marshal to json: '%s'\n", err)
			return err
		}
		fmt.Println(string(result))
		return nil
	}

	parser := jsonpath.New("").AllowMissingKeys(true)
	if err := parser.Parse(jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't parse jsonpath expression: '%s'\n", err)
		return err
	}

	buf := new(bytes.Buffer)
	if err := parser.Execute(buf, data); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't parse jsonpath expression: '%s'\n", err)
		return err

	}
	fmt.Println(buf.String())
	return nil
}
