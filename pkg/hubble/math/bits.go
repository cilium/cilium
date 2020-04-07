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

package math

// MSB returns the position of most significant bit for the given uint64
func MSB(x uint64) uint8 {
	var i uint8
	for ; (x >> i) != 0; i++ {
	}
	return i
}

// GetMask returns a bit mask filled with ones of length 'x'.
// e.g.:
// GetMask(3) => 0b00000111
// GetMask(4) => 0b00001111
// GetMask(5) => 0x00011111
func GetMask(x uint8) uint64 {
	return ^uint64(0) >> (64 - x)
}
