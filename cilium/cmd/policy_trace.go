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

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"

	"github.com/spf13/cobra"
)

var src, dst, dports []string
var verbose bool

// policyTraceCmd represents the policy_trace command
var policyTraceCmd = &cobra.Command{
	Use:   "trace -s <context> -d <context> [--dport <port>[/<protocol>]",
	Short: "Trace a policy decision",
	Long: `Verifies if source ID or LABEL(s) is allowed to consume
destination ID or LABEL(s). LABEL is represented as
SOURCE:KEY[=VALUE].
dports can be can be for example: 80/tcp, 53 or 23/udp.`,
	PreRun: verifyPolicyTrace,
	Run: func(cmd *cobra.Command, args []string) {
		srcSlice, err := parseAllowedSlice(src)
		if err != nil {
			Fatalf("Invalid source: %s", err)
		}

		dstSlice, err := parseAllowedSlice(dst)
		if err != nil {
			Fatalf("Invalid destination: %s", err)
		}

		dports, err := parseL4PortsSlice(dports)
		if err != nil {
			Fatalf("Invalid destination port: %s", err)
		}

		search := models.IdentityContext{
			From:    srcSlice,
			To:      dstSlice,
			Dports:  dports,
			Verbose: verbose,
		}

		params := NewGetPolicyResolveParams().WithIdentityContext(&search)
		if scr, err := client.Policy.GetPolicyResolve(params); err != nil {
			Fatalf("Error while retrieving policy consume result: %s\n", err)
		} else if scr != nil && scr.Payload != nil {
			fmt.Printf("%s\n", scr.Payload.Log)
			fmt.Printf("Verdict: %s\n", scr.Payload.Verdict)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyTraceCmd)
	policyTraceCmd.Flags().StringSliceVarP(&src, "src", "s", []string{}, "Source label context")
	policyTraceCmd.MarkFlagRequired("src")
	policyTraceCmd.Flags().StringSliceVarP(&dst, "dst", "d", []string{}, "Destination label context")
	policyTraceCmd.MarkFlagRequired("dst")
	policyTraceCmd.Flags().StringSliceVarP(&dports, "dport", "", []string{}, "L4 destination port to search on outgoing traffic of the source label context and on incoming traffic of the destination label context")
	policyTraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "set tracing to TRACE_VERBOSE")
}

func parseAllowedSlice(slice []string) ([]string, error) {
	inLabels := []string{}
	id := ""

	for _, v := range slice {
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			// can fail which means it needs to be a label
			inLabels = append(inLabels, v)
		} else {
			if id != "" {
				return nil, fmt.Errorf("More than one security ID provided")
			}

			id = v
		}
	}

	if id != "" {
		if len(inLabels) > 0 {
			return nil, fmt.Errorf("You can only specify either ID or labels")
		}

		resp, err := client.IdentityGet(id)
		if err != nil {
			return nil, fmt.Errorf("Unable to retrieve labels for ID %s: %s", id, err)
		}
		if resp == nil {
			return nil, fmt.Errorf("ID %s not found", id)
		}

		return resp.Labels, nil
	}
	if len(inLabels) == 0 {
		return nil, fmt.Errorf("No label or security ID provided")
	}

	return inLabels, nil
}

// parseL4PortsSlice parses a given `slice` of strings. Each string should be in
// the form of `<port>[/<protocol>]`, where the `<port>` in an integer and an
// `<protocol>` is an optional layer 4 protocol `tcp` or `udp`. In case
// `protocol` is not present, or is set to `any`, the parsed port will be set to
// `models.PortProtocolAny`.
func parseL4PortsSlice(slice []string) ([]*models.Port, error) {
	rules := []*models.Port{}
	for _, v := range slice {
		vSplit := strings.Split(v, "/")
		var protoStr string
		switch len(vSplit) {
		case 1:
			protoStr = models.PortProtocolAny
		case 2:
			protoStr = strings.ToLower(vSplit[1])
			switch protoStr {
			case models.PortProtocolTCP, models.PortProtocolUDP, models.PortProtocolAny:
			default:
				return nil, fmt.Errorf("invalid protocol %q", protoStr)
			}
		default:
			return nil, fmt.Errorf("invalid format %q. Should be <port>[/<protocol>]", v)
		}
		portStr := vSplit[0]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %s", portStr, err)
		}
		l4 := &models.Port{
			Port:     uint16(port),
			Protocol: protoStr,
		}
		rules = append(rules, l4)
	}
	return rules, nil
}

func verifyAllowedSlice(slice []string) error {
	for i, v := range slice {
		if _, err := strconv.ParseUint(v, 10, 32); err == nil {
			// can fail which means it needs to be a label
		} else if i != 0 {
			return fmt.Errorf("value %q: must be only one unsigned "+
				"number or label(s) in format of SOURCE:KEY[=VALUE]", v)
		}
	}

	return nil
}

func verifyPolicyTrace(cmd *cobra.Command, args []string) {
	if len(src) == 0 {
		Usagef(cmd, "Empty source")
	}

	if len(src) == 0 {
		Usagef(cmd, "Empty destination")
	}

	if err := verifyAllowedSlice(src); err != nil {
		Usagef(cmd, "Invalid source: %s", err)
	}

	if err := verifyAllowedSlice(dst); err != nil {
		Usagef(cmd, "Invalid destination: %s", err)
	}
}
