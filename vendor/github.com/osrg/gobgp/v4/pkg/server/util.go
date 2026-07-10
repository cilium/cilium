// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"math/rand/v2"

	"github.com/eapache/channels"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func randRange(min int, max int) int {
	return min + rand.IntN(max-min+1)
}

// randomBFDMyDiscriminator returns a non-zero 32-bit value for RFC 5880
// My Discriminator. It does not use randRange with MaxUint32 because int
// on 32-bit architectures cannot represent that upper bound.
func randomBFDMyDiscriminator() uint32 {
	for {
		v := rand.Uint32()
		if v != 0 {
			return v
		}
	}
}

func nonblockSendChannel[T any](ch chan<- T, item T) bool {
	select {
	case ch <- item:
		// sent
		return true
	default:
		// drop the item
		return false
	}
}

func drainChannel[T any](ch <-chan T) {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
			// drain the channel
		default:
			return
		}
	}
}

func cleanInfiniteChannel(ch *channels.InfiniteChannel) {
	ch.Close()
	// drain all remaining items
	drainChannel(ch.Out())
}

// Returns the binary formatted Administrative Shutdown Communication from the
// given string value.
func newAdministrativeCommunication(communication string) (data []byte) {
	if communication == "" {
		return nil
	}
	com := []byte(communication)
	if len(com) > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		data = []byte{bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX}
		data = append(data, com[:bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX]...)
	} else {
		data = []byte{byte(len(com))}
		data = append(data, com...)
	}
	return data
}

// Parses the given NOTIFICATION message data as a binary value and returns
// the Administrative Shutdown Communication in string and the rest binary.
func decodeAdministrativeCommunication(data []byte) (string, []byte) {
	if len(data) == 0 {
		return "", data
	}
	communicationLen := min(int(data[0]), bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX)
	if communicationLen > len(data)-1 {
		communicationLen = len(data) - 1
	}
	return string(data[1 : communicationLen+1]), data[communicationLen+1:]
}
