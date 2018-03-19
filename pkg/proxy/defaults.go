// Copyright 2017 Authors of Cilium
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

package proxy

import (
	"time"
)

const (
	// Size of channel (number of requests/messages) which buffers messages
	// enqueued onto proxy sockets
	socketQueueSize = 100

	// proxyConnectionCloseTimeout is the time to wait before closing both
	// connections of a proxied connection after one side has initiated the
	// closing and the other side is not being closed.
	proxyConnectionCloseTimeout = 10 * time.Second
)
