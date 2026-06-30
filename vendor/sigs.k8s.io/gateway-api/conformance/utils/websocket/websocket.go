/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package websocket

import (
	"golang.org/x/net/websocket"
)

// Dialer is an interface used to establish WebSocket connections within
// conformance tests. Like the HTTP RoundTripper and the gRPC Client, it can be
// overridden with a custom implementation whenever necessary — for example when
// the Gateway address is not directly dialable by the test runner and the
// connection must be routed through an implementation-supplied data plane.
type Dialer interface {
	// Dial opens a WebSocket connection to url, requesting the given
	// subprotocol (may be empty) and presenting origin as the Origin header.
	// The returned *websocket.Conn is used with the websocket.Message codec by
	// the conformance test.
	Dial(url, protocol, origin string) (*websocket.Conn, error)
}

// DefaultDialer is the default implementation of Dialer. It is used when a
// custom implementation is not specified, preserving the suite's historical
// behavior of dialing the Gateway address directly via websocket.Dial.
type DefaultDialer struct{}

var _ Dialer = (*DefaultDialer)(nil)

// Dial dials the WebSocket endpoint directly using golang.org/x/net/websocket.
func (d *DefaultDialer) Dial(url, protocol, origin string) (*websocket.Conn, error) {
	return websocket.Dial(url, protocol, origin)
}
