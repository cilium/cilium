// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	AWSProvider = "AWS" // AWS provider key

	// A label prefix set on a CiliumCIDRGroup that contains
	// the IPs in this group.
	LabelGroupKeyPrefix = "extgrp.cilium.io/"
)

var (
	providers lock.Map[string, GroupProviderFunc] // map with the list of providers to callback to retrieve info from.
)

// GroupProviderFunc is a func that need to be register to be able to
// register a new provider in the platform.
type GroupProviderFunc func(context.Context, *Groups) ([]netip.Addr, error)

// Groups structure to store all kinds of new integrations that needs a new
// derivative policy.
type Groups struct {
	AWS *AWSGroup `json:"aws,omitempty"`
}

// AWSGroup is an structure that can be used to whitelisting information from AWS integration
type AWSGroup struct {
	Labels              map[string]string `json:"labels,omitempty"`
	SecurityGroupsIds   []string          `json:"securityGroupsIds,omitempty"`
	SecurityGroupsNames []string          `json:"securityGroupsNames,omitempty"`
	Region              string            `json:"region,omitempty"`
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

// RegisterToGroupsProvider it will register a new callback that will be used
// when a new ToGroups rule is added.
func RegisterToGroupsProvider(providerName string, callback GroupProviderFunc) {
	providers.Store(providerName, callback)
}

// GetCidrSet will return the CIDRRule for the rule using the callbacks that
// are register in the platform.
func (group *Groups) GetCidrSet(ctx context.Context) ([]CIDRRule, error) {
	var addrs []netip.Addr
	// Get per  provider CIDRSet
	if group.AWS != nil {
		callback, ok := providers.Load(AWSProvider)
		if !ok {
			return nil, fmt.Errorf("Provider %s is not registered", AWSProvider)
		}
		awsAddrs, err := callback(ctx, group)
		if err != nil {
			return nil, fmt.Errorf(
				"Cannot retrieve data from %s provider: %w",
				AWSProvider, err)
		}
		addrs = append(addrs, awsAddrs...)
	}

	resultAddrs := ip.KeepUniqueAddrs(addrs)
	return addrsToCIDRRules(resultAddrs), nil
}
