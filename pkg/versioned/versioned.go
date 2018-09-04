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

package versioned

import (
	"strconv"
)

// Version is the version used for each Object.
type Version int64

// ParseVersion parses the given string to Version, if the string is not
// parsable a 0 Version is returned.
// If the version is bigger than int64, it will return math.MaxUint64.
func ParseVersion(s string) Version {
	i, _ := strconv.ParseInt(s, 10, 64)
	return Version(i)
}

// Object is used to store a particular interface at a specific version.
type Object struct {
	// Data is any data that can be stored in this object.
	Data interface{}
	// Version is the version used for the data stored.
	Version Version
}

// CompareVersion returns:
//  < 0 if receiver's version is older than `other` Object.
//  0 if receiver's version is the same as the `other` version.
//  > 0 if receiver's version is newer than `other` Object.
func (o *Object) CompareVersion(other Object) int64 {
	return int64(o.Version) - int64(other.Version)
}
