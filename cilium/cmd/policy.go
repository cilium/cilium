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

func createRule() *api.Rule {
	rule := api.Rule{}
	eps := api.EndpointSelector{}
	ns := api.EndpointSelector{}
	ingress := make([]api.IngressRule, 0)
	egress := make([]api.EgressRule, 0)
	//var labels labels.LabelArray
	//description := string{}

	//Create subcomponents

	//For rule.EndpointSelector
	eps_ls := slim_metav1.LabelSelector{}
	eps.LabelSelector = &eps_ls
	//eps_reqs := k8sLbls.Requirements{}
	//eps.requirements = &eps_reqs
	//eps_clss := string{}
	//eps.cachedLabelSelectorString = eps_clss

	//For rule.NodeSelector
	ns_ls := slim_metav1.LabelSelector{}
	ns.LabelSelector = &ns_ls
	//ns_reqs := k8sLbls.Requirements{}
	//ns.requirements = &ns_reqs
	//ns_clss := string{}
	//ns.cachedLabelSelectorString = ns_clss

	//For rule.Ingress
	ingressRule := api.IngressRule{}
	ingressRule.FromEndpoints = make([]api.EndpointSelector, 0)
	feps := api.EndpointSelector{}
	feps_ls := slim_metav1.LabelSelector{}
	feps.LabelSelector = &feps_ls
	//feps_reqs := k8sLbls.Requirements{}
	//feps.requirements = &feps_reqs
	//feps_clss := string{}
	//feps.cachedLabelSelectorString = feps_clss
	ingressRule.FromEndpoints = append(ingressRule.FromEndpoints, feps)

	ingressRule.FromRequires = make([]api.EndpointSelector, 0)
	frqs := api.EndpointSelector{}
	frqs_ls := slim_metav1.LabelSelector{}
	frqs.LabelSelector = &frqs_ls
	//frqs_reqs := k8sLbls.Requirements{}
	//frqs.requirements = &frqs_reqs
	//frqs_clss := string{}
	//frqs.cachedLabelSelectorString = frqs_clss
	ingressRule.FromRequires = append(ingressRule.FromRequires, frqs)

	ingressRule.ToPorts = make([]api.PortRule, 0)
	iport_rule := api.PortRule{}
	iport_rule.Ports = make([]api.PortProtocol, 0)
	iport_proto := api.PortProtocol{}
	//iport_proto.Port = string{}
	//iport_proto.Protocol = api.L4Proto{}
	iport_rule.Ports = append(iport_rule.Ports, iport_proto)
	//iport_rule.TerminatingTLS = &api.TLSContext{}
	//iport_rule.OriginatingTLS = &api.TLSContext{}
	//iport_rule.Rules = &api.L7Rules{}
	ingressRule.ToPorts = append(ingressRule.ToPorts, iport_rule)

	//ingressRule.FromCIDR = make([]api.CIDR, 0)
	//ingressRule.FromCIDRSet = make([]api.CIDRRule, 0)
	//ingressRule.FromEntities = make([]api.Entity, 0)
	//ingressRule.aggregatedSelectors = make([]api.EndpointSelector, 0)
	ingress = append(ingress, ingressRule)

	//For rule.Egress
	egressRule := api.EgressRule{}
	egressRule.ToEndpoints = make([]api.EndpointSelector, 0)
	teps := api.EndpointSelector{}
	teps_ls := slim_metav1.LabelSelector{}
	teps.LabelSelector = &teps_ls
	//teps_reqs := k8sLbls.Requirements{}
	//teps.requirements = &teps_reqs
	//teps_clss := string{}
	//teps.cachedLabelSelectorString = teps_clss
	egressRule.ToEndpoints = append(egressRule.ToEndpoints, teps)

	egressRule.ToRequires = make([]api.EndpointSelector, 0)
	trqs := api.EndpointSelector{}
	trqs_ls := slim_metav1.LabelSelector{}
	trqs.LabelSelector = &trqs_ls
	//trqs_reqs := k8sLbls.Requirements{}
	//trqs.requirements = &trqs_reqs
	//trqs_clss := string{}
	//trqs.cachedLabelSelectorString = trqs_clss
	egressRule.ToRequires = append(egressRule.ToRequires, trqs)

	egressRule.ToPorts = make([]api.PortRule, 0)
	tport_rule := api.PortRule{}
	tport_rule.Ports = make([]api.PortProtocol, 0)
	tport_proto := api.PortProtocol{}
	//tport_proto.Port = string{}
	//tport_proto.Protocol = api.L4Proto{}
	tport_rule.Ports = append(tport_rule.Ports, tport_proto)
	//tport_rule.TerminatingTLS = &api.TLSContext{}
	//tport_rule.OriginatingTLS = &api.TLSContext{}
	//tport_rule.Rules = &api.L7Rules{}
	egressRule.ToPorts = append(egressRule.ToPorts, tport_rule)

	//egressRule.ToCIDR = make([]api.CIDR, 0)
	//egressRule.ToCIDRSet = make([]api.CIDRRule, 0)
	//egressRule.ToEntities = make([]api.Entity, 0)
	//egressRule.ToServices = make([]api.Service, 0)
	//egressRule.ToFQDNs = make([]api.FQDNSelector, 0)
	//egressRule.ToGroups = make([]api.ToGroups, 0)
	//egressRule.aggregatedSelectors = make([]api.EndpointSelector,0)
	egress = append(egress, egressRule)

	rule.EndpointSelector = eps
	rule.NodeSelector = ns
	rule.Ingress = ingress
	rule.Egress = egress

	//fmt.Println(rule)

	return &rule
}

//func parseRego(content []byte, rules *api.Rules) {
//func parseRego(content []byte) {
//rule := api.Rule{}
//	ls := slim_metav1.LabelSelector{}
//var n *api.EndpointSelector
//	n := api.EndpointSelector{}
//ingress := api.IngressRule{}
//egress := api.EgressRule{}
//	n.LabelSelector = &ls
//	d := string(content)
//	lines := strings.Split(d, "\n")
//	for _, line := range lines {
//		line = strings.TrimSpace(line)
//		if strings.HasPrefix(line, "input[_].endpointSelector.matchLabels.role ==") {
//			fmt.Println("Got endpoint")
//			ml := map[string]string{}
//			ml["any.role"] = strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")
//(*rules)[0].EndpointSelector.MatchLabels = ml
//			ls.MatchLabels = ml
//		} else if strings.HasPrefix(line, "input[_].ingress[_].fromEndpoints[_].matchLabels.role ==") {
//			fmt.Println("Got ingress")
//			iml := map[string]string{}
//iml["any.role"] = strings.Split(line, "==")[1]
//			iml["any.role"] = strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")
//(*rules)[0].Ingress[0].FromEndpoints[0].MatchLabels = iml
//rule.Ingress[0].FromEndpoints[0].MatchLabels = iml
//			ls.MatchLabels = iml
//		}
//	}
//rule.EndpointSelector = n
//rule.Ingress = append(rule.Ingress, ingress)
//rule.Egress = append(rule.Egress, egress)

//	nr := createRule()
//	fmt.Println(nr)
//}

func parseRego(content []byte) {
	rule := createRule()
	var ruleList api.Rules

	d := string(content)
	lines := strings.Split(d, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "input[_].endpointSelector.matchLabels.role ==") {
			fmt.Println("Got endpoint")
			ml := map[string]string{}
			ml["any.role"] = strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")
			//(*rules)[0].EndpointSelector.MatchLabels = ml
			rule.EndpointSelector.MatchLabels = ml
		} else if strings.HasPrefix(line, "input[_].ingress[_].fromEndpoints[_].matchLabels.role ==") {
			fmt.Println("Got ingress")
			iml := map[string]string{}
			//iml["any.role"] = strings.Split(line, "==")[1]
			iml["any.role"] = strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")
			//(*rules)[0].Ingress[0].FromEndpoints[0].MatchLabels = iml
			rule.Ingress[0].FromEndpoints[0].MatchLabels = iml
			//ls.MatchLabels = iml
		} else if strings.HasPrefix(line, "input[_].ingress[_].toPorts[_].ports[_].port ==") {
			rule.Ingress[0].ToPorts[0].Ports[0].Port = strings.ReplaceAll(strings.Split(line, "==")[1], "\"", "")
		} else if strings.HasPrefix(line, "input[_].ingress[_].toPorts[_].ports[_].protocol ==") {
			rule.Ingress[0].ToPorts[0].Ports[0].Protocol = api.L4Proto(strings.ReplaceAll(strings.Split(line, "==")[1], "\"", ""))
		}
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
