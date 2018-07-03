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

	if id := identity.ReservedIdentities[args[0]]; id == identity.IdentityUnknown {
		_, _, err := endpointid.ValidateID(args[0])

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

// parseTrafficString converts the provided string to its corresponding
// TrafficDirection. If the string does not correspond to a valid TrafficDirection
// type, returns Invalid and a corresponding error.
func parseTrafficString(td string) (policymap.TrafficDirection, error) {
	lowered := strings.ToLower(td)

	switch lowered {
	case "ingress":
		return policymap.Ingress, nil
	case "egress":
		return policymap.Egress, nil
	default:
		return policymap.Invalid, fmt.Errorf("invalid direction %q provided", td)
	}

}

// updatePolicyKey updates an entry to the PolicyMap for the endpoint ID, identity,
// traffic direction, and optional list of ports in the list of arguments for the
// given command. Adds the entry to the PolicyMap if add is true, deletes if fails.
// TODO: GH-3396.
func updatePolicyKey(cmd *cobra.Command, args []string, add bool) {
	if len(args) < 3 {
		Usagef(cmd, "<endpoint id>, <traffic-direction>, and <identity> required")
	}

	trafficDirection := args[1]
	parsedTd, err := parseTrafficString(trafficDirection)
	if err != nil {
		Fatalf("Failed to convert %s to a valid traffic direction: %s", args[1], err)
	}

	endpointID := args[0]
	if numericIdentity := identity.GetReservedID(endpointID); numericIdentity != identity.IdentityUnknown {
		endpointID = "reserved_" + strconv.FormatUint(uint64(numericIdentity), 10)
	}

	policyMapPath := bpf.MapPath(policymap.MapName + endpointID)
	policyMap, _, err := policymap.OpenMap(policyMapPath)
	if err != nil {
		Fatalf("Cannot open policymap '%s' : %s", policyMapPath, err)
	}

	peerLbl, err := strconv.ParseUint(args[2], 10, 32)
	if err != nil {
		Fatalf("Failed to convert %s", args[2])
	}

	port := uint16(0)
	protos := []uint8{}
	if len(args) > 3 {
		pp, err := parseL4PortsSlice([]string{args[3]})
		if err != nil {
			Fatalf("Failed to parse L4: %s", err)
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

	label := uint32(peerLbl)
	for _, proto := range protos {
		u8p := u8proto.U8proto(proto)
		entry := fmt.Sprintf("%d %d/%s", label, port, u8p.String())
		if add == true {
			if err := policyMap.Allow(label, port, u8p, parsedTd); err != nil {
				Fatalf("Cannot add policy key '%s': %s\n", entry, err)
			}
		} else {
			if err := policyMap.Delete(label, port, u8p, parsedTd); err != nil {
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
		if enabled, err := option.NormalizeBool(Opts[k]); err != nil {
			Fatalf("Invalid option answer %s: %s", Opts[k], err)
		} else if enabled {
			fmt.Printf("%-24s %s\n", k, color.Green("Enabled"))
		} else {
			fmt.Printf("%-24s %s\n", k, color.Red("Disabled"))
		}
	}
}
