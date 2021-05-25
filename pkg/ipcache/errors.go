// Copyright 2021 Authors of Cilium
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

package ipcache

import (
	"fmt"

	"github.com/cilium/cilium/pkg/source"
)

// ErrOverwrite represents an overwrite error where functions return the error
// to indicate the new source can't overwrite existing source.
type ErrOverwrite struct {
	ExistingSrc source.Source
	NewSrc      source.Source
}

// NewErrOverwrite returns a new ErrOverwrite.
func NewErrOverwrite(existing, new source.Source) *ErrOverwrite {
	return &ErrOverwrite{
		ExistingSrc: existing,
		NewSrc:      new,
	}
}

func (e ErrOverwrite) Error() string {
	return fmt.Sprintf("unable to overwrite source %q with source %q", e.ExistingSrc, e.NewSrc)
}

func (e *ErrOverwrite) Is(target error) bool {
	t, ok := target.(*ErrOverwrite)
	if !ok {
		return false
	}
	return (e.ExistingSrc == t.ExistingSrc || t.ExistingSrc == "") &&
		(e.NewSrc == t.NewSrc || t.NewSrc == "")
}

// ErrInvalidIP represents an error of an invalid IP.
type ErrInvalidIP struct {
	ip string
}

// NewErrInvalidIP returns a new ErrInvalidIP.
func NewErrInvalidIP(ip string) *ErrInvalidIP {
	return &ErrInvalidIP{
		ip: ip,
	}
}

func (e ErrInvalidIP) Error() string {
	return fmt.Sprintf("attempt to upsert invalid IP %q into ipcache layer", e.ip)
}

func (e *ErrInvalidIP) Is(target error) bool {
	t, ok := target.(*ErrInvalidIP)
	if !ok {
		return false
	}
	return e.ip == t.ip
}
