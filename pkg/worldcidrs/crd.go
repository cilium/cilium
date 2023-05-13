// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrs

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ParseCWCIDR takes a CiliumWorldCIDRSet CR and converts it to a CIDRSet,
// the internal representation of the CIDR sets.
func ParseCWCIDR(cwcidr *v2alpha1.CiliumWorldCIDRSet) (*CIDRSet, error) {
	var cidrList []*net.IPNet

	name := cwcidr.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("CiliumWorldCIDRSet must have a name")
	}

	for _, cidrString := range cwcidr.Spec.WorldCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumWorldCIDRSetName: name}).Warn("Error parsing CIDR")
			return nil, err
		}
		cidrList = append(cidrList, cidr)
	}

	return &CIDRSet{
		id: types.NamespacedName{
			Name: name,
		},
		cidrs: cidrList,
	}, nil
}

// ParseCWCIDRSetID takes a CiliumWorldCIDRSet CR and returns only its ID.
func ParseCWCIDRSetID(cwcidr *v2alpha1.CiliumWorldCIDRSet) types.NamespacedName {
	return CIDRSetID{
		Name: cwcidr.Name,
	}
}
