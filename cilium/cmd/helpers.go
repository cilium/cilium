// Copyright 2016-2019 Authors of Cilium
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
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/color"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/spf13/cobra"
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

	if id := identity.GetReservedID(args[0]); id == identity.IdentityUnknown {
		_, _, err := endpointid.Parse(args[0])

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

// TablePrinter prints the map[string][]string, which is an usual representation
// of dumped BPF map, using tabwriter.
func TablePrinter(firstTitle, secondTitle string, data map[string][]string) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintf(w, "%s\t%s\t\n", firstTitle, secondTitle)

	for key, value := range data {
		for k, v := range value {
			if k == 0 {
				fmt.Fprintf(w, "%s\t%s\t\n", key, v)
			} else {
				fmt.Fprintf(w, "%s\t%s\t\n", "", v)
			}
		}
	}

	w.Flush()
}

// Search 'result' for strings with escaped JSON inside, and expand the JSON.
func expandNestedJSON(result bytes.Buffer) (bytes.Buffer, error) {
	reStringWithJSON := regexp.MustCompile(`"[^"\\{]*{.*[^\\]"`)
	reJSON := regexp.MustCompile(`{.*}`)
	for {
		var (
			loc    []int
			indent string
		)

		// Search for nested JSON; if we don't find any, then break.
		resBytes := result.Bytes()
		if loc = reStringWithJSON.FindIndex(resBytes); loc == nil {
			break
		}

		// Determine the current indentation
		for i := 0; i < loc[0]-1; i++ {
			idx := loc[0] - i - 1
			if resBytes[idx] != ' ' {
				break
			}
			indent = fmt.Sprintf("\t%s\t", indent)
		}

		stringStart := loc[0]
		stringEnd := loc[1]

		// Unquote the string with the nested json.
		quotedBytes := resBytes[stringStart:stringEnd]
		unquoted, err := strconv.Unquote(string(quotedBytes))
		if err != nil {
			return bytes.Buffer{}, fmt.Errorf("Failed to Unquote string: %s\n%s", err.Error(), string(quotedBytes))
		}

		// Find the JSON within the quoted string.
		nestedStart := 0
		nestedEnd := 0
		if locs := reJSON.FindAllStringIndex(unquoted, -1); locs != nil {
			// The last match is the longest one.
			last := len(locs) - 1
			nestedStart = locs[last][0]
			nestedEnd = locs[last][1]
		} else if reJSON.Match(quotedBytes) {
			// The entire string is JSON
			nestedEnd = len(unquoted)
		}

		// Decode the nested JSON
		decoded := ""
		if nestedEnd != 0 {
			m := make(map[string]interface{})
			nested := bytes.NewBufferString(unquoted[nestedStart:nestedEnd])
			if err := json.NewDecoder(nested).Decode(&m); err != nil {
				return bytes.Buffer{}, fmt.Errorf("Failed to decode nested JSON: %s", err.Error())
			}
			decodedBytes, err := json.MarshalIndent(m, indent, "  ")
			if err != nil {
				return bytes.Buffer{}, fmt.Errorf("Cannot marshal nested JSON: %s", err.Error())
			}
			decoded = string(decodedBytes)
		}

		// Serialize
		nextResult := bytes.Buffer{}
		nextResult.Write(resBytes[0:stringStart])
		nextResult.WriteString(string(unquoted[:nestedStart]))
		nextResult.WriteString(string(decoded))
		nextResult.WriteString(string(unquoted[nestedEnd:]))
		nextResult.Write(resBytes[stringEnd:])
		result = nextResult
	}

	return result, nil
}

// PolicyUpdateArgs is the parsed representation of a
// bpf policy {add,delete} command.
type PolicyUpdateArgs struct {
	// endpointID is the identity of the endpoint provided as
	// argument. If this identity is a reserved identity, then
	// it is prefixed with 'reserved_'.
	endpointID string

	// trafficDirection represents the traffic direction provided
	// as an argument e.g. `ingress`
	trafficDirection trafficdirection.TrafficDirection

	// label represents the identity of the label provided as argument.
	label uint32

	// port represents the port associated with the command, if specified.
	port uint16

	// protocols represents the set of protocols associated with the
	// command, if specified.
	protocols []uint8
}

// parseTrafficString converts the provided string to its corresponding
// TrafficDirection. If the string does not correspond to a valid TrafficDirection
// type, returns Invalid and a corresponding error.
func parseTrafficString(td string) (trafficdirection.TrafficDirection, error) {
	lowered := strings.ToLower(td)

	switch lowered {
	case "ingress":
		return trafficdirection.Ingress, nil
	case "egress":
		return trafficdirection.Egress, nil
	default:
		return trafficdirection.Invalid, fmt.Errorf("invalid direction %q provided", td)
	}

}

// parsePolicyUpdateArgs parses the arguments to a bpf policy {add,delete}
// command, provided as a list containing the endpoint ID, traffic direction,
// identity and optionally, a list of ports.
// Returns a parsed representation of the command arguments.
func parsePolicyUpdateArgs(cmd *cobra.Command, args []string) *PolicyUpdateArgs {
	if len(args) < 3 {
		Usagef(cmd, "<endpoint id>, <traffic-direction>, and <identity> required")
	}

	pa, err := parsePolicyUpdateArgsHelper(args)
	if err != nil {
		Fatalf("%s", err)
	}

	return pa
}

func parsePolicyUpdateArgsHelper(args []string) (*PolicyUpdateArgs, error) {
	trafficDirection := args[1]
	parsedTd, err := parseTrafficString(trafficDirection)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert %s to a valid traffic direction: %s", args[1], err)
	}

	endpointID := args[0]
	if numericIdentity := identity.GetReservedID(endpointID); numericIdentity != identity.IdentityUnknown {
		endpointID = "reserved_" + strconv.FormatUint(uint64(numericIdentity), 10)
	}

	peerLbl, err := strconv.ParseUint(args[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert %s", args[2])
	}
	label := uint32(peerLbl)

	port := uint16(0)
	protos := []uint8{}
	if len(args) > 3 {
		pp, err := parseL4PortsSlice([]string{args[3]})
		if err != nil {
			return nil, fmt.Errorf("Failed to parse L4: %s", err)
		}
		port = pp[0].Port
		if port != 0 {
			proto, _ := u8proto.ParseProtocol(pp[0].Protocol)
			if proto == 0 {
				for _, proto := range u8proto.ProtoIDs {
					protos = append(protos, uint8(proto))
				}
			} else {
				protos = append(protos, uint8(proto))
			}
		}
	}
	if len(protos) == 0 {
		protos = append(protos, 0)
	}

	pa := &PolicyUpdateArgs{
		endpointID:       endpointID,
		trafficDirection: parsedTd,
		label:            label,
		port:             port,
		protocols:        protos,
	}

	return pa, nil
}

// updatePolicyKey updates an entry in the PolicyMap for the provided
// PolicyUpdateArgs argument.
// Adds the entry to the PolicyMap if add is true, otherwise the entry is
// deleted.
func updatePolicyKey(pa *PolicyUpdateArgs, add bool) {
	policyMapPath := bpf.MapPath(policymap.MapName + pa.endpointID)
	policyMap, _, err := policymap.OpenOrCreate(policyMapPath)
	if err != nil {
		Fatalf("Cannot open policymap '%s' : %s", policyMapPath, err)
	}

	for _, proto := range pa.protocols {
		u8p := u8proto.U8proto(proto)
		entry := fmt.Sprintf("%d %d/%s", pa.label, pa.port, u8p.String())
		if add {
			var proxyPort uint16
			if err := policyMap.Allow(pa.label, pa.port, u8p, pa.trafficDirection, proxyPort); err != nil {
				Fatalf("Cannot add policy key '%s': %s\n", entry, err)
			}
		} else {
			if err := policyMap.Delete(pa.label, pa.port, u8p, pa.trafficDirection); err != nil {
				Fatalf("Cannot delete policy key '%s': %s\n", entry, err)
			}
		}
	}
}

// dumpConfig pretty prints boolean options
func dumpConfig(Opts map[string]string) {
	opts := []string{}
	for k := range Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		// XXX: Reuse the format function from *option.Library
		value = Opts[k]
		if enabled, err := option.NormalizeBool(value); err != nil {
			// If it cannot be parsed as a bool, just format the value.
			fmt.Printf("%-24s %s\n", k, color.Green(value))
		} else if enabled == option.OptionDisabled {
			fmt.Printf("%-24s %s\n", k, color.Red("Disabled"))
		} else {
			fmt.Printf("%-24s %s\n", k, color.Green("Enabled"))
		}
	}
}
