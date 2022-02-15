// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"strconv"

	"github.com/sirupsen/logrus"
)

const eniIndexTagKey = "cilium-eni-index"

// GetENIIndexFromTags get ENI index from tags
func GetENIIndexFromTags(tags map[string]string) int {
	v, ok := tags[eniIndexTagKey]
	if !ok {
		return 0
	}
	index, err := strconv.Atoi(v)
	if err != nil {
		logrus.WithError(err).Warning("Unable to retrieve index from ENI")
	}
	return index
}

// FillTagWithENIIndex set the index to tags
func FillTagWithENIIndex(tags map[string]string, index int) map[string]string {
	tags[eniIndexTagKey] = strconv.Itoa(index)
	return tags
}
