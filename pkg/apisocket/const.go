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

package apisocket

import "os"

const (
	// GroupFilePath is the unix group file path.
	GroupFilePath = "/etc/group"
	// CiliumGroupName is the cilium's unix group name.
	CiliumGroupName = "cilium"
	// SocketFileMode is the default file mode for the sockets.
	SocketFileMode os.FileMode = 0660
)
