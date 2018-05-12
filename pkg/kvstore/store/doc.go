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

// Package store implements a shared store backed by a kvstore or similar with
// the following properties:
//
// * A single type is used to represent all keys
// * Any number of collaborators can join the store. Typically a collaborator
//   is an individual Cilium agent running on each node.
// * All collaborators can own and contribute keys to the store. Each key is
//   owned by exactly one collaborator. It is the responsibility of each
//   collaborator to pick a key name which is guaranteed to be unique.
// * All collaborate desire to see all keys within the scope of a store. The
//   scope of the store is defined by a common key prefix. For this purpose,
//   each collaborator maintains a local cache of all keys in the store by
//   subscribing to change events.
package store
