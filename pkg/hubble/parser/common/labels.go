// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	"net"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
)

func FilterCIDRLabels(log logrus.FieldLogger, labels []string) []string {
	// Cilium might return a bunch of cidr labels with different prefix length. Filter out all
	// but the longest prefix cidr label, which can be useful for troubleshooting. This also
	// relies on the fact that when a Cilium security identity has multiple CIDR labels, longer
	// prefix is always a subset of shorter prefix.
	cidrPrefix := "cidr:"
	var filteredLabels []string
	var maxSize int
	var maxStr string
	for _, label := range labels {
		if !strings.HasPrefix(label, cidrPrefix) {
			filteredLabels = append(filteredLabels, label)
			continue
		}
		currLabel := strings.TrimPrefix(label, cidrPrefix)
		// labels for IPv6 addresses are represented with - instead of : as
		// : cannot be used in labels; make sure to convert it to a valid
		// IPv6 representation
		currLabel = strings.Replace(currLabel, "-", ":", -1)
		_, curr, err := net.ParseCIDR(currLabel)
		if err != nil {
			log.WithField("label", label).Warn("got an invalid cidr label")
			continue
		}
		if currMask, _ := curr.Mask.Size(); currMask > maxSize {
			maxSize, maxStr = currMask, label
		}
	}
	if maxSize != 0 {
		filteredLabels = append(filteredLabels, maxStr)
	}
	return filteredLabels
}

func SortAndFilterLabels(log logrus.FieldLogger, labels []string, securityIdentity identity.NumericIdentity) []string {
	if securityIdentity.HasLocalScope() {
		labels = FilterCIDRLabels(log, labels)
	}
	sort.Strings(labels)
	return labels
}
