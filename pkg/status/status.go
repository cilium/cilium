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

package status

import (
	"fmt"

	"github.com/cilium/cilium/common"
)

// Code indicates different levels of severity for status entries
type Code int

const (
	// OK indicates the status is OK
	OK Code = 0

	// Warning indicates a temporary warning state that can typically be
	// recovered from
	Warning Code = -1

	// Failure indicates a permanent failure and typically requires
	// intervention
	Failure Code = -2

	// Disabled indicates that the component in question has been disabled
	Disabled Code = -3
)

func (sc Code) ColorString() string {
	var text string
	switch sc {
	case OK:
		text = common.Green("OK")
	case Warning:
		text = common.Yellow("Warning")
	case Failure:
		text = common.Red("Failure")
	case Disabled:
		text = common.Yellow("Disabled")
	default:
		text = "Unknown code"
	}
	return fmt.Sprintf("%s", text)
}

func (sc Code) String() string {
	switch sc {
	case OK:
		return "OK"
	case Warning:
		return "Warning"
	case Failure:
		return "Failure"
	case Disabled:
		return "Disabled"
	default:
		return "Unknown code"
	}
}

// Type represents the type for the given status. A greater value
// indicates a higher priority
type Type int

const (
	// BPF represents the BPF datapath layer
	BPF Type = 200

	// Policy represents the policy enforcement layer
	Policy Type = 100

	// Other represents all other status messages
	Other Type = 0
)

// TypeSlice represents a slice of Type, is used for sorting
// purposes.
type TypeSlice []Type

// Len returns the length of the slice.
func (p TypeSlice) Len() int { return len(p) }

// Less returns true if the element `j` is less than element `i`.
// *It's reversed* so that we can sort the slice by high to lowest priority.
func (p TypeSlice) Less(i, j int) bool { return p[i] > p[j] }

// Swap swaps element in `i` with element in `j`.
func (p TypeSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
