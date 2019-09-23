// Copyright 2019 Authors of Cilium
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

// Package events represents the events map for communication with the datapath.
// It is used by the BPF code to emit notifications when events occur, whether
// they be debug messages, trace notifications, errors, or dropped packets.
// pkg/monitor layers on top of this to provide an event listener API.
// +groupName=maps
package events
