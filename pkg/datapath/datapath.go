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

	// Node must return the handler for node events
	Node() NodeHandler

	// LocalNodeAddressing must return the node addressing implementation
	// of the local node
	LocalNodeAddressing() NodeAddressing

	// InstallProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	InstallProxyRules(proxyPort uint16, ingress bool, name string) error

	// RemoveProxyRules creates the necessary datapath config (e.g., iptables
	// rules for redirecting host proxy traffic on a specific ProxyPort)
	RemoveProxyRules(proxyPort uint16, ingress bool, name string) error

	// SupportsOriginalSourceAddr tells if the datapath supports
	// use of original source addresses in proxy upstream
	// connections.
	SupportsOriginalSourceAddr() bool

	// Loader must return the implementation of the loader, which is responsible
	// for loading, reloading, and compiling datapath programs.
	Loader() Loader
}
