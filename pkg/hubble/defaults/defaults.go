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

package defaults

const (
	// ServerPort is the default port for hubble server when a provided
	// listen address does not include one.
	ServerPort = 4244

	// RelayPort is the default port for the hubble-relay server.
	RelayPort = 4245

	// GRPCServiceName is the name of the Hubble gRPC service.
	GRPCServiceName = "hubble-grpc"

	// DomainName specifies the domain name to use when constructing the server
	// name for peer change notifications.
	DomainName = "cilium.io"
)
