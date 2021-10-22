//  Copyright 2021 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package srv6policy

import (
	"fmt"
	"net"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/types"
)

// Config is the internal representation of CiliumEgressSRv6Policy.
type Config struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []*net.IPNet
	sid               net.IP
}

// PolicyID includes endpoint name and namespace
type endpointID = types.NamespacedName

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type endpointMetadata struct {
	// Endpoint labels
	labels map[string]string
	// Endpoint ID
	id endpointID
	// ipv4s are endpoint's unique IPv4 addresses
	ipv4s []net.IP
	// ipv6s are endpoint's unique IPv6 addresses
	ipv6s []net.IP
}

// policyConfigSelectsEndpoint determines if the given endpoint is selected by the policy
// config based on matching labels of config and endpoint.
func (config *Config) policyConfigSelectsEndpoint(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

// Parse takes a CiliumEgressSRv6Policy CR and converts to Config, the internal
// representation of the egress nat policy
func Parse(cesrp *v2alpha1.CiliumEgressSRv6Policy) (*Config, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet

	name := cesrp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("CiliumEgressSRv6Policy must have a name")
	}

	for _, cidrString := range cesrp.Spec.DestinationCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressSRv6PolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, egressRule := range cesrp.Spec.Egress {
		if egressRule.PodSelector == nil {
			return nil, fmt.Errorf("CiliumEgressSRv6Policy cannot have nil pod selector")
		}
		endpointSelectorList = append(
			endpointSelectorList,
			api.NewESFromK8sLabelSelector("", egressRule.PodSelector))
	}

	return &Config{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		sid:               net.ParseIP(cesrp.Spec.DestinationSID).To16(),
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseConfigID takes a CiliumEgressSRv6Policy CR and returns only the config id.
func ParseConfigID(cesrp *v2alpha1.CiliumEgressSRv6Policy) types.NamespacedName {
	return policyID{
		Name: cesrp.Name,
	}
}
