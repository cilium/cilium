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
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/ip"
)

const (
	AWSProvider = "AWS" // AWS provider key
)

var (
	providers = sync.Map{} // map with the list of providers to callback to retrieve info from.
)

// GroupProviderFunc is a func that need to be register to be able to
// register a new provider in the platform.
type GroupProviderFunc func(context.Context, *ToGroups) ([]net.IP, error)

// ToGroups structure to store all kinds of new integrations that needs a new
// derivative policy.
type ToGroups struct {
	AWS *AWSGroup `json:"aws,omitempty"`
}

// AWSGroup is an structure that can be used to whitelisting information from AWS integration
type AWSGroup struct {
	Labels              map[string]string `json:"labels,omitempty"`
	SecurityGroupsIds   []string          `json:"securityGroupsIds,omitempty"`
	SecurityGroupsNames []string          `json:"securityGroupsNames,omitempty"`
	Region              string            `json:"region,omitempty"`
}

// RegisterToGroupsProvider it will register a new callback that will be used
// when a new ToGroups rule is added.
func RegisterToGroupsProvider(providerName string, callback GroupProviderFunc) {
	providers.Store(providerName, callback)
}

// GetCidrSet will return the CIDRRule for the rule using the callbacks that
// are register in the platform.
func (group *ToGroups) GetCidrSet(ctx context.Context) ([]CIDRRule, error) {

	var ips []net.IP
	// Get per  provider CIDRSet
	if group.AWS != nil {
		callbackInterface, ok := providers.Load(AWSProvider)
		if !ok {
			return nil, fmt.Errorf("Provider %s is not registered", AWSProvider)
		}
		callback, ok := callbackInterface.(GroupProviderFunc)
		if !ok {
			return nil, fmt.Errorf("Provider callback for %s is not a valid instance", AWSProvider)
		}
		awsIPs, err := callback(ctx, group)
		if err != nil {
			return nil, fmt.Errorf(
				"Cannot retrieve data from %s provider: %s",
				AWSProvider, err)
		}
		ips = append(ips, awsIPs...)
	}

	resultIps := ip.KeepUniqueIPs(ips)
	return IPsToCIDRRules(resultIps), nil
}
