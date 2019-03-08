// Copyright 2016-2017 Authors of Cilium
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

package types

import (
	"net"
)

// IPv6 is the binary representation for encoding in binary structs.
type IPv6 [16]byte

func (v6 IPv6) IP() net.IP {
	return v6[:]
}

func (v6 IPv6) DuplicateIP() net.IP {
	dup := make([]byte, 16)
	copy(dup, v6[:])
	return dup
}

func (v6 IPv6) String() string {
	return v6.IP().String()
}
