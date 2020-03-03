// Copyright 2019 Authors of Hubble
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

package time

import (
	"fmt"
	"time"
)

var (
	// Now is a hijackable function for time.Now() that makes unit testing a lot
	// easier for stuff that relies on relative time.
	Now = time.Now
)

// FromString takes as input a string in either RFC3339 or time.Duration
// format in the past and converts it to a time.Time.
func FromString(input string) (time.Time, error) {
	// try as relative duration first
	d, err := time.ParseDuration(input)
	if err == nil {
		return Now().Add(-d), nil
	}

	// try as rfc3339
	t, err := time.Parse(time.RFC3339, input)
	if err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf(
		"failed to convert %s to time", input,
	)
}
