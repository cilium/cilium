// Copyright 2018 Authors of Cilium
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

package api

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"sync"
)

const (
	AWSPROVIDER = "AWS" // AWS provider key
)

var (
	// @TODO move this to sync.Map
	providers = providersCallbacks{}
)

// ProviderIntegration is a func that need to be register to be able to
// register a new provider in the platform.
type ProviderIntegration func(*ToGroups) ([]net.IP, error)

// ToGroups structure to store all kinds of new integrations that needs a new
// child policy.
type ToGroups struct {
	Aws *AWSGroups `json:"aws,omitempty"`
}

// AWSGroups is the structure that can be used to whitelisting information from AWS integration
type AWSGroups struct {
	Labels              map[string]string `json:"labels,omitempty"`
	SecurityGroupsIds   []string          `json:"securityGroupsIds,omitempty"`
	SecurityGroupsNames []string          `json:"securityGroupsNames,omitempty"`
	Region              string            `json:"region,omitempty"`
}

// RegisterToGroupsProvider it will register a new callback that will be used
// when a new ToGroups rule is added.
func RegisterToGroupsProvider(providerName string, callback ProviderIntegration) {
	providers.Store(providerName, callback)
}

// GetCidrSet will return the CIDRRule for the rule using the callbacks that
// are register in the platform.
func (group *ToGroups) GetCidrSet() ([]CIDRRule, error) {

	var ips []net.IP

	emptyResult := []CIDRRule{}

	// Get per  provider CIDRSet
	if group.Aws != nil {
		callbackInterface, ok := providers.Load(AWSPROVIDER)
		if !ok {
			return emptyResult, fmt.Errorf("Provider %s is not registered", AWSPROVIDER)
		}
		callback := callbackInterface.(ProviderIntegration)
		awsIPs, err := callback(group)
		if err != nil {
			return emptyResult, fmt.Errorf(
				"Cannot retrieve data from %s provider: %s",
				AWSPROVIDER, err)
		}
		ips = append(ips, awsIPs...)
	}

	uniqueIPs := []net.IP{}
	IPUniqueMap := map[string]bool{}
	for _, ip := range ips {
		if _, ok := IPUniqueMap[ip.String()]; ok {
			continue
		}
		IPUniqueMap[ip.String()] = true
		uniqueIPs = append(uniqueIPs, ip)
	}

	// Sort IPS to have always the same result and do not update policies if it
	// is not needed.
	sort.Slice(uniqueIPs, func(i, j int) bool {
		return bytes.Compare(ips[i], ips[j]) < 0
	})
	return IpsToCIDRRules(uniqueIPs), nil
}

type providersCallbacks struct {
	sync.Map
}
