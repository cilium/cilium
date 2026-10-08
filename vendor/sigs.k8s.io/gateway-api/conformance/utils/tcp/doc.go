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

// TCP contains a basic TCP client for tcp-backend assertions
// Opposite to HTTP client, this client can be extremely simple, always running
// the right commands against the TCP Server, expecting a response and then closing
// the connection.
// The client optionally accepts an expected TLS response, meaning it should verify
// if the TCP answer contains TLS attributes. This option can be used to validate that
// it is communicating with a TLS enabled backend (and can be used for Passthrough assertions)

package tcp
