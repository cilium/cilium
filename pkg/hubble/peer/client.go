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

package peer

import (
	"io"

	peerpb "github.com/cilium/cilium/api/v1/peer"
)

// Client defines an interface that Peer service client should implement.
type Client interface {
	peerpb.PeerClient
	io.Closer
}

// ClientBuilder creates a new Client.
type ClientBuilder interface {
	// Target returns the address that Client connects to.
	Target() string
	// Client builds a new Client.
	Client() (Client, error)
}
