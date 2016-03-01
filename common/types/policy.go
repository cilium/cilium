package types

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Privilege byte

const (
	ALLOW Privilege = iota
	REQUIRES
)

type LabelSelector string

func (l *LabelSelector) Expand(node *PolicyNode) string {
	return fmt.Sprintf("%s.%s", node.FullName(), l)
}

// Base type for all PolicyRule* types
type PolicyRuleBase struct {
	Coverage []LabelSelector `json:"Coverage,omitempty"`
}

// Allow the following consumers
type PolicyRuleConsumers struct {
	PolicyRuleBase
	Allow []string `json:"Allow"`
}

// Any further consumer requires the specified list of
// labels in order to consume
type PolicyRuleRequires struct {
	PolicyRuleBase
	Requires []string `json:"Requires"`
}

type Port struct {
	proto  string `json:"Protocol"`
	number int    `json:"Number"`
}

type PolicyRulePorts struct {
	PolicyRuleBase
	Ports []Port `json:"Ports"`
}

// Do not allow further rules of specified type
type PolicyRuleDropPrivileges struct {
	PolicyRuleBase
	DropPrivileges []Privilege `json:"Drop-privileges"`
}

// Node to define hierarchy of rules
type PolicyNode struct {
	Name     string
	Parent   *PolicyNode            `json:"-"`
	Rules    []interface{}          `json:"Rules,omitempty"`
	Children map[string]*PolicyNode `json:"Children,omitempty"`
}

// Overall policy tree
type PolicyTree struct {
	Root PolicyNode
}

func (pn *PolicyNode) FullName() string {
	if pn.Parent != nil {
		s := fmt.Sprintf("%s.%s", pn.Parent.FullName(), pn.Name)
		fmt.Printf("Building FullName: %s\n", s)
		return s
	}

	fmt.Printf("Building FullName: io.cilium\n")
	return "io.cilium"
}

func (pn *PolicyNode) UnmarshalJSON(data []byte) error {
	var policyNode struct {
		Name     string                 `json:"Name,omitempty"`
		Rules    []*json.RawMessage     `json:"Rules,omitempty"`
		Children map[string]*PolicyNode `json:"Children,omitempty"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&policyNode); err != nil {
		return fmt.Errorf("Decode of PolicyNode failed: %+v", err)
	}

	pn.Name = policyNode.Name
	pn.Children = policyNode.Children

	// Fill out "Name" field of children which ommited it in the JSON
	for k, _ := range policyNode.Children {
		pn.Children[k].Name = k
		pn.Children[k].Parent = pn
	}

	for _, rawMsg := range policyNode.Rules {
		var om map[string]*json.RawMessage

		if err := json.Unmarshal(*rawMsg, &om); err != nil {
			return err
		}

		if _, ok := om["Allow"]; ok {
			var pr_c PolicyRuleConsumers

			if err := json.Unmarshal(*rawMsg, &pr_c); err != nil {
				return err
			}

			pn.Rules = append(pn.Rules, pr_c)
		} else if _, ok := om["Requires"]; ok {
			var pr_r PolicyRuleRequires

			if err := json.Unmarshal(*rawMsg, &pr_r); err != nil {
				return err
			}

			pn.Rules = append(pn.Rules, pr_r)
		} else {
			return fmt.Errorf("Unknown policy rule object: %+v", om)
		}
	}

	return nil
}
