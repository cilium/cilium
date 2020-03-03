// Copyright 2018-2019 Authors of Cilium
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

// Package eppolicymap represents the map from an endpoint ID to its policy map.
// This map is of type bpf.MapTypeHashOfMaps where the key is the endpoint ID.
// It is used to lookup the policy from the socket context where unlike in the
// L2/L3 context, where the program has a direct lookup of the policy because
// each program is attached to an endpoint, socket programs run on all sockets
// regardless of endpoint.
// +groupName=maps
package eppolicymap
