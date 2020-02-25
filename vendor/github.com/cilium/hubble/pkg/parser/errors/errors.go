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

package errors

import (
	"errors"
	"fmt"
)

var (
	// ErrEmptyData gets returns when monitoring payload contained no data
	ErrEmptyData = errors.New("empty data")
)

// ErrInvalidType specifies when it was given a packet type that was not
// possible to be decoded by the decoder.
type ErrInvalidType struct {
	invalidType byte
}

// NewErrInvalidType returns a new ErrInvalidType
func NewErrInvalidType(invalidType byte) error {
	return ErrInvalidType{invalidType: invalidType}
}

func (e ErrInvalidType) Error() string {
	return fmt.Sprintf("can't decode following payload type: %v", e.invalidType)
}

// IsErrInvalidType returns true if the given error is type of ErrInvalidType
func IsErrInvalidType(err error) bool {
	_, ok := err.(ErrInvalidType)
	return ok
}
