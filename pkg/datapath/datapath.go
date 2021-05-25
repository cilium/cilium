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

package datapath

// Datapath is the interface to abstract all datapath interactions. The
// abstraction allows to implement the datapath requirements with multiple
// implementations
type Datapath interface {
	ConfigWriter
	IptablesManager

	// Node must return the handler for node events
	Node() NodeHandler

	// LocalNodeAddressing must return the node addressing implementation
	// of the local node
	LocalNodeAddressing() NodeAddressing

	// Loader must return the implementation of the loader, which is responsible
	// for loading, reloading, and compiling datapath programs.
	Loader() Loader

	// WireguardAgent returns the Wireguard agent for the local node
	WireguardAgent() WireguardAgent
}
