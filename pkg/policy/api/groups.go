// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/cilium/cilium/pkg/labels"
)

const (
	// A label prefix set on a CiliumCIDRGroup that contains
	// the IPs in this group.
	LabelGroupKeyPrefix = "extgrp.cilium.io/"
)

// Groups allows referencing CIDRs that are resolved from an external integration.
type Groups struct {
	AWS *AWSGroup `json:"aws,omitempty"`
}

// AWSGroup is an structure that can be used to whitelisting information from AWS integration
type AWSGroup struct {
	// Labels selects AWS ENIs by labels.
	// Multiple labels are AND-ed together.
	Labels map[string]string `json:"labels,omitempty"`

	// SecurityGroupsIds selects VPC SecurityGroups by IDs.
	// If multiple IDs are specified, they are OR-ed together.
	//
	// Note that this may be AND-ed with any Names specified. Specifying both
	// IDs and Names is not recommended.
	SecurityGroupsIds []string `json:"securityGroupsIds,omitempty"`

	// SecurityGroupsNames selects VPC SecurityGroups by name.
	// If multiple names are specified, they are OR-ed together.
	//
	// Note that this may be AND-ed with any IDs specified. Specifying both
	// IDs and Names is not recommended.
	SecurityGroupsNames []string `json:"securityGroupsNames,omitempty"`

	// Deprecated: Region is unused.
	Region string `json:"region,omitempty"`
}

// Hash hashes this group to a standard key. This is used to reference the group
// when generating downstream resources.
func (g *Groups) Hash() string {
	if g == nil {
		return ""
	}

	b, err := json.Marshal(g)
	if err != nil {
		// unreachable; we already loaded this from JSON via the apiserver...
		return ""
	}
	sum := sha256.New224().Sum(b)
	return base64.RawURLEncoding.EncodeToString(sum)[0:63]
}

// LabelKey returns a unique label key for this group, in the format of
// extgrp.cilium.io/<sha224>.
// This can be used to reference the group in dependent resources.
//
// The hash is part of the label key, not the label value, to prevent collisions
// if the same IP is referenced by multiple groups.
func (g *Groups) LabelKey() string {
	return LabelGroupKeyPrefix + g.Hash()
}

// Implementation of APISelector type

// SelectorKey is a string representation of this selector.
func (g Groups) SelectorKey() string {
	return labels.LabelSourceCIDRGroup + ":" + g.LabelKey()
}

// GetAsEndpointSelector converts this Group in to the underlying label selector
// for CIDRGroups.
//
// A separate controller resolves external groups and upserts them to a CiliumCIDRGroup.
func (g *Groups) GetAsEndpointSelector() EndpointSelector {
	return NewESFromLabels(labels.NewLabel(g.LabelKey(), "", labels.LabelSourceCIDRGroup))
}
