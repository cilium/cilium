// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"slices"

	"github.com/spf13/pflag"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var _ pflag.Value = &monitorAPI.MessageTypeFilter{}

// GetAllTypes returns a slice of all known message types, sorted
func GetAllTypes() []string {
	types := make([]string, 0, len(monitorAPI.MessageTypeNames))
	for k := range monitorAPI.MessageTypeNames {
		types = append(types, k)
	}
	slices.Sort(types)
	return types
}
