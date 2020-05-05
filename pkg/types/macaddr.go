// Copyright 2020 Authors of Cilium
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

// MACAddr is the binary representation for encoding in binary structs.
type MACAddr [6]byte

func (addr MACAddr) hardwareAddr() net.HardwareAddr {
	return addr[:]
}

func (addr MACAddr) String() string {
	return addr.hardwareAddr().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (addr *MACAddr) DeepCopyInto(out *MACAddr) {
	copy(out[:], addr[:])
	return
}
