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

package channel

// ReadB attempts to read a boolean value out of the specified channel, and
// will return immediately regardless of whether a value is read or not.
//
// If a value is read from the channel, a pointer to the value is returned as
// the first result, otherwise it is nil. The second result determines whether
// the socket is open (true) or closed (false).
func ReadB(c chan bool) (*bool, bool) {
	select {
	case res, open := <-c:
		if open {
			return &res, open
		}
		return nil, false
	default:
		// Channel receive didn't return immediately; must be open.
		break
	}

	return nil, true
}

// IsOpenB returns whether the specified channel is open without blocking. If a
// value is sent on the channel when this check occurs, the value may be lost.
// Therefore, if any operation is executed on the channel other than a close(),
// then ReadBoolNonBlocking should be used instead.
func IsOpenB(c chan bool) bool {
	_, res := ReadB(c)
	return res
}

// CloseB closes the specified channel if it is open.
func CloseB(c chan bool) {
	if IsOpenB(c) {
		close(c)
	}
}
