// Copyright 2016-2019 Authors of Cilium
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

// IPv4 is the binary representation for encoding in binary structs.
type IPv4 [4]byte

func (v4 IPv4) IP() net.IP {
	return v4[:]
}

func (v4 IPv4) String() string {
	return v4.IP().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (v4 *IPv4) DeepCopyInto(out *IPv4) {
	copy(out[:], v4[:])
	return
}
