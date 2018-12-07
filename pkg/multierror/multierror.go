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

package multierror

// Multierror is the error implementation which stores multiple errors.
type Multierror struct {
	errors []error
}

// Error merges all error messages into one string with semicolon as a
// separator.
func (m *Multierror) Error() string {
	// path.Join accepts only slices of strings as an argument. It's easier
	// to implement its simplier version here than to bother with type
	// conversion.
	switch len(m.errors) {
	case 0:
		return ""
	case 1:
		return m.errors[0].Error()
	}
	msg := m.errors[0].Error()
	for _, err := range m.errors[1:] {
		msg += "; "
		msg += err.Error()
	}
	return msg
}

// Append adds the error to the slice. It takes care of initialization of the
// slice if it's nil.
func Append(m *Multierror, err error) *Multierror {
	if m == nil {
		errors := make([]error, 0, 1)
		m = &Multierror{errors: errors}

	}
	m.errors = append(m.errors, err)
	return m
}
