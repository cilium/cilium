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

//+build armbe arm64be mips mips64 ppc64

package byteorder

var Native binary.ByteOrder = binary.BigEndian

func HostToNetwork16(u uint16) uint16 { return u }
func HostToNetwork32(u uint32) uint32 { return u }
func NetworkToHost16(u uint16) uint16 { return u }
func NetworkToHost32(u uint32) uint32 { return u }
