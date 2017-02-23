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

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/urfave/cli"
)

var (
	ignoredMasksSource = []string{".git"}
	ignoredMasks       []*regexp.Regexp
	cliPolicy          cli.Command
)

func init() {
	ignoredMasks = make([]*regexp.Regexp, len(ignoredMasksSource))

	for i := range ignoredMasksSource {
		ignoredMasks[i] = regexp.MustCompile(ignoredMasksSource[i])
	}

	cliPolicy = cli.Command{
		Name:  "policy",
		Usage: "Manage policy operations",
		Subcommands: []cli.Command{
			{
				Name:      "validate",
				Usage:     "Validate a policy (sub)tree",
				Action:    validatePolicy,
				ArgsUsage: "<path>",
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "dump, d",
						Usage: "Dump parsed policy tree after validation",
					},
				},
				Before: verifyArgumentsValidate,
			},
			{
				Name:      "import",
				Usage:     "Import a policy (sub)tree",
				Action:    importPolicy,
				ArgsUsage: "<path>",
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "echo, e",
						Usage: "Echo the inserted policy after successful insertion",
					},
				},
				Before: verifyArgumentsValidate,
			},
			{
				Name:      "dump",
				Usage:     "Dump policy (sub)tree",
				Action:    dumpPolicy,
				ArgsUsage: "<path>",
			},
			{
				Name:      "delete",
				Usage:     "Delete policy (sub)tree",
				Action:    deletePolicy,
				ArgsUsage: "<path>",
				Flags: []cli.Flag{
					cli.StringSliceFlag{
						Name:  "coverage, c",
						Usage: "Coverage for the given path. [SOURCE:]KEY[=VALUE]",
					},
				},
				Before: verifyArgumentsValidate,
			},
			{
				Name:   "get-id",
				Usage:  "Lookup security context id",
				Action: getSecID,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "list, l",
						Usage: "List all reserved IDs",
					},
				},
			},
			{
				Name: "allowed",
				Usage: "Verifies if source ID or LABEL(s) is allowed to consume destination ID or LABEL(s). " +
					"LABEL is represented as SOURCE:KEY[=VALUE]",
				Action: verifyPolicy,
				Flags: []cli.Flag{
					cli.StringSliceFlag{
						Name: "source, s",
					},
					cli.StringSliceFlag{
						Name: "destination, d",
					},
				},
				Before: verifyArgumentsPolicy,
			},
		},
	}
}

func verifyArgumentsValidate(ctx *cli.Context) error {
	path := ctx.Args().First()
	if path == "" {
		return fmt.Errorf("Error: empty path")
	}
	return nil
}

func verifyAllowedSlice(slice []string) error {
	for i, v := range slice {
		if _, err := strconv.ParseUint(v, 10, 32); err != nil {
			// can fail which means it needs to be a label
			labels.ParseLabel(v)
		} else if i != 0 {
			return fmt.Errorf("value %q: must be only one unsigned "+
				"number or label(s) in format of SOURCE:KEY[=VALUE]", v)
		}
	}
	return nil
}

func verifyArgumentsPolicy(ctx *cli.Context) error {
	srcSlice := ctx.StringSlice("source")
	if len(srcSlice) == 0 {
		return fmt.Errorf("Empty source")
	}

	dstSlice := ctx.StringSlice("destination")
	if len(srcSlice) == 0 {
		return fmt.Errorf("Empty destination")
	}

	if err := verifyAllowedSlice(srcSlice); err != nil {
		return fmt.Errorf("Invalid source: %s", err)
	}

	if err := verifyAllowedSlice(dstSlice); err != nil {
		return fmt.Errorf("Invalid destination: %s", err)
	}

	return nil
}

func getContext(content []byte, offset int64) (int, string, int) {
	if offset >= int64(len(content)) || offset < 0 {
		return 0, fmt.Sprintf("[error: Offset %d is out of bounds 0..%d]", offset, len(content)), 0
	}

	lineN := strings.Count(string(content[:offset]), "\n") + 1

	start := strings.LastIndexByte(string(content[:offset]), '\n')
	if start == -1 {
		start = 0
	} else {
		start++
	}

	end := strings.IndexByte(string(content[start:]), '\n')
	l := ""
	if end == -1 {
		l = string(content[start:])
	} else {
		end = end + start
		l = string(content[start:end])
	}

	return lineN, l, (int(offset) - start)
}

func handleUnmarshalError(f string, content []byte, err error) error {
	switch e := err.(type) {
	case *json.SyntaxError:
		line, ctx, off := getContext(content, e.Offset)

		if off <= 1 {
			return fmt.Errorf("malformed policy, not JSON?")
		}

		preoff := off - 1
		pre := make([]byte, preoff)
		copy(pre, ctx[:preoff])
		for i := 0; i < preoff && i < len(pre); i++ {
			if pre[i] != '\t' {
				pre[i] = ' '
			}
		}

		return fmt.Errorf("%s:%d: syntax error at offset %d:\n%s\n%s^",
			path.Base(f), line, off, ctx, pre)
	case *json.UnmarshalTypeError:
		line, ctx, off := getContext(content, e.Offset)
		return fmt.Errorf("%s:%d: unable to assign value '%s' to type '%v':\n%s\n%*c",
			path.Base(f), line, e.Value, e.Type, ctx, off, '^')
	default:
		return fmt.Errorf("%s: unknown error:%s", path.Base(f), err)
	}
}

func loadPolicyFile(path string) (*policy.Node, error) {
	var content []byte
	var err error
	log.Debugf("Loading file %s", path)

	if path == "-" {
		content, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
	} else {
		content, err = ioutil.ReadFile(path)
	}

	if err != nil {
		return nil, err
	}

	var policyNode policy.Node
	err = json.Unmarshal(content, &policyNode)
	if err != nil {
		return nil, handleUnmarshalError(path, content, err)
	}

	return &policyNode, nil
}

func ignoredFile(name string) bool {
	for i := range ignoredMasks {
		if ignoredMasks[i].MatchString(name) {
			log.Debugf("Ignoring file %s", name)
			return true
		}
	}

	return false
}

func loadPolicy(name string) (*policy.Node, error) {
	log.Debugf("Entering directory %s...", name)

	if name == "-" {
		return loadPolicyFile(name)
	}

	if fi, err := os.Stat(name); err != nil {
		return nil, err
	} else if fi.Mode().IsRegular() {
		return loadPolicyFile(name)
	} else if !fi.Mode().IsDir() {
		return nil, fmt.Errorf("Error: %s is not a file or a directory", name)
	}

	files, err := ioutil.ReadDir(name)
	if err != nil {
		return nil, err
	}

	var node *policy.Node

	// process all files first
	for _, f := range files {
		if f.IsDir() || ignoredFile(path.Base(f.Name())) {
			continue
		}

		if p, err := loadPolicyFile(filepath.Join(name, f.Name())); err != nil {
			return nil, err
		} else {
			if node != nil {
				if _, err := node.Merge(p); err != nil {
					return nil, fmt.Errorf("Error: %s: %s", f.Name(), err)
				}
			} else {
				node = p
			}
		}
	}

	// recursive search
	for _, f := range files {
		if f.IsDir() {
			if ignoredFile(path.Base(f.Name())) {
				continue
			}
			subpath := filepath.Join(name, f.Name())
			if p, err := loadPolicy(subpath); err != nil {
				return nil, err
			} else {
				if p.Name == "" {
					return nil, fmt.Errorf("Policy node import from %s did not derive a name",
						subpath)
				}

				node.AddChild(p.Name, p)
			}
		}
	}

	log.Debugf("Leaving directory %s...", name)

	return node, nil
}

func importPolicy(ctx *cli.Context) {
	path := ctx.Args().First()
	if node, err := loadPolicy(path); err != nil {
		Fatalf("Could not import policy %s: %s\n", path, err)
	} else {
		log.Debugf("Constructed policy object for import %+v", node)

		// Ignore request if no policies have been found
		if node == nil {
			return
		}

		jsonPolicy := node.JSONMarshal()
		if resp, err := client.PolicyPut(node.Name, jsonPolicy); err != nil {
			Fatalf("Could not import policy directory %s: %s\n", path, err)
		} else if ctx.Bool("echo") {
			fmt.Printf("%s\n", resp)
		}
	}
}

func prettyPrint(node *policy.Node) {
	if node == nil {
		fmt.Println("No policy loaded.")
	} else if b, err := json.MarshalIndent(node, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "Could not marshal response: %s\n", err)
	} else {
		fmt.Printf("%s\n", b)
	}
}

func validatePolicy(ctx *cli.Context) {
	path := ctx.Args().First()
	if node, err := loadPolicy(path); err != nil {
		Fatalf("Validation of %s failed\n%s\n", path, err)
	} else {
		fmt.Printf("All policy elements are valid.\n")

		if ctx.Bool("dump") {
			fmt.Printf("%s\n", node.DebugString(1))
			prettyPrint(node)
		}
	}
}

func dumpPolicy(ctx *cli.Context) {
	path := ctx.Args().First()
	if resp, err := client.PolicyGet(path); err != nil {
		Fatalf("Could not retrieve policy for: %s: %s\n", path, err)
	} else {
		fmt.Printf("%s\n", resp)
	}
}

func deletePolicy(ctx *cli.Context) {
	path := ctx.Args().Get(0)
	if err := client.PolicyDelete(path); err != nil {
		Fatalf("Could not delete node policy for: %s: %s\n", path, err)
	}
}

func getSecID(ctx *cli.Context) {
	if ctx.Bool("list") {
		for k, v := range policy.ReservedIdentities {
			fmt.Printf("%-15s %3d\n", k, v)
		}
		return
	}

	lbl := ctx.Args().First()

	if id := policy.GetReservedID(lbl); id != policy.ID_UNKNOWN {
		fmt.Printf("%d\n", id)
	} else {
		os.Exit(1)
	}
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
	} else {
		if len(inLabels) == 0 {
			return nil, fmt.Errorf("No label or security ID provided")
		}

		return inLabels, nil
	}
}

func verifyPolicy(ctx *cli.Context) {
	srcInSlice := ctx.StringSlice("source")
	dstInSlice := ctx.StringSlice("destination")

	srcSlice, err := parseAllowedSlice(srcInSlice)
	if err != nil {
		Fatalf("Invalid source: %s\n", err)
	}

	dstSlice, err := parseAllowedSlice(dstInSlice)
	if err != nil {
		Fatalf("Invalid destination: %s\n", err)
	}

	search := models.IdentityContext{
		From: srcSlice,
		To:   dstSlice,
	}

	params := NewGetPolicyResolveParams().WithIdentityContext(&search)
	scr, err := client.Policy.GetPolicyResolve(params)
	if err != nil {
		Fatalf("Error while retrieving policy consume result: %s\n", err)
	}

	if scr != nil && scr.Payload != nil {
		fmt.Printf("%s\n", scr.Payload.Log)
		fmt.Printf("Verdict: %s\n", scr.Payload.Verdict)
	}
}
