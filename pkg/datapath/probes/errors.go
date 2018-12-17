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

package probes

import (
	"errors"
)

var (
	// ErrMissingKernelConfig represents an error when kernel configuration
	// was not found.
	ErrMissingKernelConfig = errors.New("missing kernel configuration")
)

// IsErrMissingKernelConfig returns true if the given error is the type of
// ErrMissingKernelConfig.
func IsErrMissingKernelConfig(err error) bool {
	return err == ErrMissingKernelConfig
}
