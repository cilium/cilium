// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
