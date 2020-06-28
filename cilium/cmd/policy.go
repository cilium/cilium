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
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	//k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	//"github.com/cilium/cilium/pkg/labels"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
}

var (
	ignoredMasksSource = []string{".git"}
	ignoredMasks       []*regexp.Regexp
)

func init() {
	ignoredMasks = make([]*regexp.Regexp, len(ignoredMasksSource))

	for i := range ignoredMasksSource {
		ignoredMasks[i] = regexp.MustCompile(ignoredMasksSource[i])
	}

	rootCmd.AddCommand(policyCmd)
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
	var l string
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

func ignoredFile(name string) bool {
	for i := range ignoredMasks {
		if ignoredMasks[i].MatchString(name) {
			logrus.WithField(logfields.Path, name).Debug("Ignoring file")
			return true
		}
	}

	return false
}

func createEndpoint() api.EndpointSelector {
	eps := api.EndpointSelector{}
	eps.LabelSelector = &slim_metav1.LabelSelector{}
	return eps
}

func createLabelSelector() *slim_metav1.LabelSelector {
	return new(slim_metav1.LabelSelector)
}

func createMatchLabel(key string, val string) map[string]string {
	m := make(map[string]string)
	m[key] = val
	return m
}

func createAndPopulatePortRule(lines *[]string, line_no int) (*api.PortRule, int) {
	var i int
	portrule := new(api.PortRule)
	portproto := new(api.PortProtocol)

	for i = line_no; i < len(*lines); {
		line := strings.TrimSpace((*lines)[i])
		if strings.HasPrefix(line, "input[_].ingress[_].toPorts[_].ports[_].port") {
			portproto.Port = strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")
		} else if strings.HasPrefix(line, "input[_].ingress[_].toPorts[_].ports[_].protocol") {
			portproto.Protocol = api.L4Proto(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", ""))
			portrule.Ports = append(portrule.Ports, (*portproto))
		} else {
			break
		}
		i = i + 1
	}

	return portrule, i
}

func createAndPopulateIngressRule(lines *[]string, line_no int) (*api.IngressRule, int) {
	ingrule := new(api.IngressRule)
	var i int
	var port_rule *api.PortRule

	for i = line_no; i < len(*lines); {
		line := strings.TrimSpace((*lines)[i])
		if strings.HasPrefix(line, "input[_].ingress[_].fromEndpoints[_]") {
			// Found endpoint "from" which ingress is allowed
			// Create an endpoint object for the same and put it in the
			// corresponding slice of api.IngressRule
			eps := createEndpoint()
			eps.LabelSelector = createLabelSelector()
			eps.MatchLabels = createMatchLabel("any.role", strings.TrimSpace(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")))
			ingrule.FromEndpoints = append(ingrule.FromEndpoints, eps)
		} else if strings.HasPrefix(line, "input[_].ingress[_].fromRequires[_]") {
			// Found endpoint consraints
			// Create an endpoint object for the same and put it in the
			// corresponding slice of api.IngressRule
			eps := createEndpoint()
			eps.LabelSelector = createLabelSelector()
			eps.MatchLabels = createMatchLabel("any.role", strings.TrimSpace(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")))
			ingrule.FromEndpoints = append(ingrule.FromEndpoints, eps)
		} else if strings.HasPrefix(line, "input[_].ingress[_].toPorts[_].ports[_]") {
			// Found ToPorts section of the ingress rule
			// Allocate and initialize a api.PortRule object and put it
			// in corresponding slice of api.IngressRule object
			port_rule, i = createAndPopulatePortRule(lines, i)
			ingrule.ToPorts = append(ingrule.ToPorts, (*port_rule))
		} else if strings.HasPrefix(line, "input[_].ingress[_].toPorts[_].rule") {
			fmt.Println("Layer 7 rules not supported yet")
		} else {
			// This function only processes ingress rules so it should not
			// process other lines
			break
		}

		i = i + 1
	}

	return ingrule, i
}

func createAndPopulateEgressRule(lines *[]string, line_no int) (*api.EgressRule, int) {
	egrule := new(api.EgressRule)
	var i int
	var port_rule *api.PortRule

	for i = line_no; i < len(*lines); {
		line := strings.TrimSpace((*lines)[i])
		if strings.HasPrefix(line, "input[_].egress[_].toEndpoints[_]") {
			// Found endpoint "from" which ingress is allowed
			// Create an endpoint object for the same and put it in the
			// corresponding slice of api.IngressRule
			eps := createEndpoint()
			eps.LabelSelector = createLabelSelector()
			eps.MatchLabels = createMatchLabel("any.role", strings.TrimSpace(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")))
			egrule.ToEndpoints = append(egrule.ToEndpoints, eps)
		} else if strings.HasPrefix(line, "input[_].egress[_].toRequires[_]") {
			// Found endpoint consraints
			// Create an endpoint object for the same and put it in the
			// corresponding slice of api.IngressRule
			eps := createEndpoint()
			eps.LabelSelector = createLabelSelector()
			eps.MatchLabels = createMatchLabel("any.role", strings.TrimSpace(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")))
			egrule.ToEndpoints = append(egrule.ToEndpoints, eps)
		} else if strings.HasPrefix(line, "input[_].egress[_].toPorts[_].ports[_]") {
			// Found ToPorts section of the ingress rule
			// Allocate and initialize a api.PortRule object and put it
			// in corresponding slice of api.IngressRule object
			port_rule, i = createAndPopulatePortRule(lines, i)
			egrule.ToPorts = append(egrule.ToPorts, (*port_rule))
		} else if strings.HasPrefix(line, "input[_].egress[_].toPorts[_].rule") {
			fmt.Println("Layer 7 rules not supported yet")
		} else {
			// This function only processes ingress rules so it should not
			// process other lines
			break
		}

		i = i + 1
	}

	return egrule, i

}

func createAndPopulateRule(lines *[]string, line_no int) (*api.Rule, int) {
	// Create an api.Rule object
	rule := new(api.Rule)
	var i int
	var ingress_rule *api.IngressRule
	var egress_rule *api.EgressRule

	// Process subsequent lines to populate Rule
	for i = line_no; i < len(*lines); {
		line := strings.TrimSpace((*lines)[i])
		if strings.HasPrefix(line, "input[_].labels[_]") {
			// Found label "for" the rule
			// Put it under Label field of api.Rule
			fmt.Println("Labels not yet supported")
		} else if strings.HasPrefix(line, "input[_].endpointSelector") {
			// Found endpoint "for" the rule
			// Allocate and initialize the endpoint and put it into rule
			// object
			rule.EndpointSelector = createEndpoint()
			rule.EndpointSelector.LabelSelector = createLabelSelector()
			rule.EndpointSelector.MatchLabels = createMatchLabel("any.role",
				strings.TrimSpace(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")))
		} else if strings.HasPrefix(line, "input[_].nodepointSelector") {
			// Found endpoint "for" the rule
			// Allocate and initialize the endpoint and put it into rule
			// object
			rule.NodeSelector = createEndpoint()
			rule.NodeSelector.LabelSelector = createLabelSelector()
			rule.NodeSelector.MatchLabels = createMatchLabel("any.role",
				strings.TrimSpace(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")))
		} else if strings.HasPrefix(line, "input[_].ingress[_]") {
			// Found "ingress" section of the rule
			// Allocate and initialize an api.IngressRule object and put
			// that into this api.Rule object
			ingress_rule, i = createAndPopulateIngressRule(lines, i)
			rule.Ingress = append(rule.Ingress, (*ingress_rule))
		} else if strings.HasPrefix(line, "input[_].egress[_]") {
			// Found "egress" section of the rule
			// Allocate and initialize an api.IngressRule object and put
			// that into this api.Rule object
			egress_rule, i = createAndPopulateEgressRule(lines, i)
			rule.Egress = append(rule.Egress, (*egress_rule))
		} else if strings.HasPrefix(line, "}") { // End of rule block
			break
		}

		i = i + 1 // Resume scanning from  next line
	}

	return rule, i
}

func parseRego(content []byte) {
	var ruleList api.Rules
	var rule *api.Rule

	d := string(content)
	lines := strings.Split(d, "\n")

	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "allow = true") {
			fmt.Println("Found policy. Create Cilium Rule object.")
			rule, i = createAndPopulateRule(&lines, i+1) // For allow==true, called function will process rule from next line
		}

		i = i + 1 //resume scanning from next line
	}

	ruleList = append(ruleList, rule)
	fmt.Println(ruleList)
}

func loadPolicyFile(path string) (api.Rules, error) {
	var content []byte
	var err error
	logrus.WithField(logfields.Path, path).Debug("Loading file")

	if path == "-" {
		content, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
	} else {
		content, err = ioutil.ReadFile(path)
	}

	if err != nil {
		return nil, err
	}

	var ruleList api.Rules

	if strings.HasSuffix(path, ".rego") {
		//rule := api.Rule{}
		parseRego(content)
		//ruleList = append(ruleList, rule)
		fmt.Println("Rego files detected")
	} else {
		err = json.Unmarshal(content, &ruleList)
		if err != nil {
			return nil, handleUnmarshalError(path, content, err)
		}
	}

	return ruleList, nil
}

func loadPolicy(name string) (api.Rules, error) {
	logrus.WithField(logfields.Path, name).Debug("Entering directory")

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

	result := api.Rules{}
	ruleList, err := processAllFilesFirst(name, files)
	if err != nil {
		return nil, err
	}
	result = append(result, ruleList...)

	ruleList, err = recursiveSearch(name, files)
	if err != nil {
		return nil, err
	}
	result = append(result, ruleList...)

	logrus.WithField(logfields.Path, name).Debug("Leaving directory")

	return result, nil
}

func processAllFilesFirst(name string, files []os.FileInfo) (api.Rules, error) {
	result := api.Rules{}

	for _, f := range files {
		if f.IsDir() || ignoredFile(path.Base(f.Name())) {
			continue
		}

		ruleList, err := loadPolicyFile(filepath.Join(name, f.Name()))
		if err != nil {
			return nil, err
		}

		result = append(result, ruleList...)
	}

	return result, nil
}

func recursiveSearch(name string, files []os.FileInfo) (api.Rules, error) {
	result := api.Rules{}
	for _, f := range files {
		if f.IsDir() {
			if ignoredFile(path.Base(f.Name())) {
				continue
			}
			subpath := filepath.Join(name, f.Name())
			ruleList, err := loadPolicy(subpath)
			if err != nil {
				return nil, err
			}
			result = append(result, ruleList...)
		}
	}
	return result, nil
}
