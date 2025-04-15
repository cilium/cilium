// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"log/slog"
	"strconv"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const eniIndexTagKey = "cilium-eni-index"

// GetENIIndexFromTags get ENI index from tags
func GetENIIndexFromTags(logger *slog.Logger, tags map[string]string) int {
	v, ok := tags[eniIndexTagKey]
	if !ok {
		return 0
	}
	index, err := strconv.Atoi(v)
	if err != nil {
		logger.Warn(
			"Unable to retrieve index from ENI",
			logfields.Error, err,
		)
	}
	return index
}

// FillTagWithENIIndex set the index to tags
func FillTagWithENIIndex(tags map[string]string, index int) map[string]string {
	tags[eniIndexTagKey] = strconv.Itoa(index)
	return tags
}
