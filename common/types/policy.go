package types

import ()

type Privilege int

const (
	ALLOW Privilege = iota
	REQUIRES
)

// Base type for all PolicyRule* types
type PolicyRule struct {
	Coverage string `json:"coverage"`
}

// Allow the following consumers
type PolicyRuleConsumers struct {
	PolicyRule
	Allow []string `json:"allow"`
}

// Any further consumer requires the specified list of
// labels in order to consume
type PolicyRuleRequires struct {
	PolicyRule
	Requires []string `json:"requires"`
}

// Do not allow further rules of specified type
type PolicyDropPrivileges struct {
	PolicyRule
	DropPrivileges []Privilege `json:"drop-privileges"`
}

// Node to define hierarchy of rules
type PolicyNode struct {
	Name   string
	Rules  []interface{} `json:"rules"`
	Childs []PolicyNode  `json:"childs"`
}

// Overall policy tree
type PolicyTree struct {
	Root PolicyNode
}
