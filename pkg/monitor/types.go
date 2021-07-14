// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium

package monitor

import (
	"sort"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/spf13/pflag"
)

var _ pflag.Value = &monitorAPI.MessageTypeFilter{}

// GetAllTypes returns a slice of all known message types, sorted
func GetAllTypes() []string {
	types := make([]string, len(monitorAPI.MessageTypeNames))
	i := 0
	for k := range monitorAPI.MessageTypeNames {
		types[i] = k
		i++
	}
	sort.Strings(types)
	return types
}
