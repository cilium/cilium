// Copyright 2016-2018 Authors of Cilium
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

package monitor

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

// Must be synchronized with <bpf/lib/common.h>
const (
	// 0-128 are reserved for BPF datapath events
	MessageTypeUnspec = iota
	MessageTypeDrop
	MessageTypeDebug
	MessageTypeCapture
	MessageTypeTrace

	// 129-255 are reserved for agent level events

	// MessageTypeAccessLog contains a pkg/proxy/accesslog.LogRecord
	MessageTypeAccessLog = 129

	// MessageTypeAgent is an agent notification carrying a AgentNotify
	MessageTypeAgent = 130
)

var (
	names = map[string]int{
		"drop":    MessageTypeDrop,
		"debug":   MessageTypeDebug,
		"capture": MessageTypeCapture,
		"trace":   MessageTypeTrace,
		"l7":      MessageTypeAccessLog,
		"agent":   MessageTypeAgent,
	}
)

func type2name(typ int) string {
	for name, value := range names {
		if value == typ {
			return name
		}
	}

	return strconv.Itoa(typ)
}

type MessageTypeFilter []int

var _ pflag.Value = &MessageTypeFilter{}

func (m *MessageTypeFilter) String() string {
	pieces := make([]string, 0, len(*m))
	for _, typ := range *m {
		pieces = append(pieces, type2name(typ))
	}

	return strings.Join(pieces, ",")
}

func (m *MessageTypeFilter) Set(value string) error {
	i, err := names[value]
	if !err {
		return fmt.Errorf("Unknown type (%s). Please use one of the following ones %v", value, GetAllTypes())
	}

	*m = append(*m, i)
	return nil
}

func (m *MessageTypeFilter) Type() string {
	return "[]string"
}

func (m *MessageTypeFilter) Contains(typ int) bool {
	for _, v := range *m {
		if v == typ {
			return true
		}
	}

	return false
}

// GetAllTypes returns a slice of all known message types, sorted
func GetAllTypes() []string {
	types := make([]string, len(names))
	i := 0
	for k := range names {
		types[i] = k
		i++
	}
	sort.Strings(types)
	return types
}
