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

package option

import (
	"fmt"
	"strconv"
	"strings"
)

// MonitorAggregationLevel represents a level of aggregation for monitor events
// from the datapath. Low values represent no aggregation, that is, to increase
// the number of events emitted from the datapath; Higher values represent more
// aggregation, to minimize the number of events emitted from the datapath.
//
// The MonitorAggregationLevel does not affect the Debug option in the daemon
// or endpoint, so debug notifications will continue uninhibited by this
// setting.
type MonitorAggregationLevel OptionSetting

const (
	// MonitorAggregationLevelNone represents no aggregation in the
	// datapath; all packets will be monitored.
	MonitorAggregationLevelNone OptionSetting = 0

	// MonitorAggregationLevelLow represents aggregation of monitor events
	// to emit a maximum of one trace event per packet. Trace events when
	// packets are received are disabled.
	MonitorAggregationLevelLowest OptionSetting = 1

	// MonitorAggregationLevelLow is the same as
	// MonitorAggregationLevelLowest, but may aggregate additional traffic
	// in future.
	MonitorAggregationLevelLow OptionSetting = 2

	// MonitorAggregationLevelMedium represents aggregation of monitor
	// events to only emit notifications periodically for each connection
	// unless there is new information (eg, a TCP connection is closed).
	MonitorAggregationLevelMedium OptionSetting = 3

	// MonitorAggregationLevelMax is the maximum level of aggregation
	// currently supported.
	MonitorAggregationLevelMax OptionSetting = 4
)

// monitorAggregationOption maps a user-specified string to a monitor
// aggregation level.
var monitorAggregationOption = map[string]OptionSetting{
	"":         MonitorAggregationLevelNone,
	"none":     MonitorAggregationLevelNone,
	"disabled": MonitorAggregationLevelNone,
	"lowest":   MonitorAggregationLevelLowest,
	"low":      MonitorAggregationLevelLow,
	"medium":   MonitorAggregationLevelMedium,
	"max":      MonitorAggregationLevelMax,
	"maximum":  MonitorAggregationLevelMax,
}

func init() {
	for i := MonitorAggregationLevelNone; i <= MonitorAggregationLevelMax; i++ {
		number := strconv.Itoa(int(i))
		monitorAggregationOption[number] = OptionSetting(i)
	}
}

// monitorAggregationFormat maps an aggregation level to a formatted string.
var monitorAggregationFormat = map[OptionSetting]string{
	MonitorAggregationLevelNone:   "None",
	MonitorAggregationLevelLowest: "Lowest",
	MonitorAggregationLevelLow:    "Low",
	MonitorAggregationLevelMedium: "Medium",
	MonitorAggregationLevelMax:    "Max",
}

// VerifyMonitorAggregationLevel validates the specified key/value for a
// monitor aggregation level.
func VerifyMonitorAggregationLevel(key, value string) error {
	_, err := ParseMonitorAggregationLevel(value)
	return err
}

// ParseMonitorAggregationLevel turns a string into a monitor aggregation
// level. The string may contain an integer value or a string representation of
// a particular monitor aggregation level.
func ParseMonitorAggregationLevel(value string) (OptionSetting, error) {
	// First, attempt the string representation.
	if level, ok := monitorAggregationOption[strings.ToLower(value)]; ok {
		return level, nil
	}

	// If it's not a valid string option, attempt to parse an integer.
	valueParsed, err := strconv.Atoi(value)
	if err != nil {
		err = fmt.Errorf("invalid monitor aggregation level %q", value)
		return MonitorAggregationLevelNone, err
	}
	parsed := OptionSetting(valueParsed)
	if parsed < MonitorAggregationLevelNone || parsed > MonitorAggregationLevelMax {
		err = fmt.Errorf("monitor aggregation level must be between %d and %d",
			MonitorAggregationLevelNone, MonitorAggregationLevelMax)
		return MonitorAggregationLevelNone, err
	}
	return parsed, nil
}

// FormatMonitorAggregationLevel maps a MonitorAggregationLevel to a string.
func FormatMonitorAggregationLevel(level OptionSetting) string {
	return monitorAggregationFormat[level]
}
