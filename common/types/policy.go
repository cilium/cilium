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

// Base type for all PolicyRule* types
type PolicyRule struct {
}

// Allow the following consumers
type PolicyRuleConsumers struct {
	Coverage []string `json:"Coverage,omitempty"`
	Allow    []string `json:"Allow"`
}

// Any further consumer requires the specified list of
// labels in order to consume
type PolicyRuleRequires struct {
	Coverage []string `json:"Coverage,omitempty"`
	Requires []string `json:"Requires"`
}

type Port struct {
	proto  string `json:"Protocol"`
	number int    `json:"Number"`
}

type PolicyRulePorts struct {
	Coverage []string `json:"Coverage,omitempty"`
	Ports    []Port   `json:"Ports"`
}

// Do not allow further rules of specified type
type PolicyRuleDropPrivileges struct {
	Coverage       []string    `json:"Coverage,omitempty"`
	DropPrivileges []Privilege `json:"Drop-privileges"`
}

// Node to define hierarchy of rules
type PolicyNode struct {
	Name     string                 `json:"Name,omitempty"`
	Rules    []PolicyRule           `json:"Rules,omitempty"`
	Children map[string]*PolicyNode `json:"Children,omitempty"`
}

// Overall policy tree
type PolicyTree struct {
	Root PolicyNode
}

func (pr *PolicyRule) UnmarshalJSON(data []byte) error {
	var om map[string]*json.RawMessage

	if err := json.Unmarshal(data, &om); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))

	if _, ok := om["Allow"]; ok {
		var pr_c PolicyRuleConsumers

		if err := decoder.Decode(&pr_c); err != nil {
			return fmt.Errorf("Decode of PolicyNode failed: %+v", err)
		}

		fmt.Printf("PolicyRuleConsumers: %+v", pr_c)
	} else if _, ok := om["Requires"]; ok {
		var pr_r PolicyRuleRequires

		if err := decoder.Decode(&pr_r); err != nil {
			return fmt.Errorf("Decode of PolicyNode failed: %+v", err)
		}

		fmt.Printf("PolicyRuleRequires: %+v", pr_r)
	} else {
		return fmt.Errorf("Unknown policy rule object: %+v", om)
	}

	return nil
}
