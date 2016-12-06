//
// Copyright 2016 Authors of Cilium
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
//
package labels

type ReservedID uint32

const (
	ID_NAME_ALL   = "all"
	ID_NAME_HOST  = "host"
	ID_NAME_WORLD = "world"
)

const (
	ID_UNKNOWN ReservedID = iota
	ID_HOST
	ID_WORLD
)

var (
	ResDec = map[string]ReservedID{
		ID_NAME_HOST:  ID_HOST,
		ID_NAME_WORLD: ID_WORLD,
	}
	ResEnc = map[ReservedID]string{
		ID_HOST:  ID_NAME_HOST,
		ID_WORLD: ID_NAME_WORLD,
	}
)

func (id ReservedID) String() string {
	if v, exists := ResEnc[id]; exists {
		return v
	}

	return ""
}

func GetID(name string) ReservedID {
	if v, ok := ResDec[name]; ok {
		return v
	}
	return ID_UNKNOWN
}
