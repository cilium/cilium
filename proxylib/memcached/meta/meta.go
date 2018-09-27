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

// text memcache protocol parser based on https://github.com/memcached/memcached/blob/master/doc/protocol.txt

package meta

// MemcacheMeta gathers information about memcache frame for L7 rules matching
type MemcacheMeta struct {
	// for text protocol
	Command string
	// for binary protocol
	Opcode byte
	Keys   [][]byte
}

// IsBinary tells whether meta instance is for text or binary protocol
func (m *MemcacheMeta) IsBinary() bool {
	return len(m.Command) == 0
}
