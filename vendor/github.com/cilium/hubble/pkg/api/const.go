// Copyright 2019 Authors of Hubble
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

package api

import (
	"os"
	"time"
)

const (
	// GroupFilePath is the unix group file path.
	GroupFilePath = "/etc/group"
	// HubbleGroupName is the hubble's default unix group name. Set HUBBLE_GROUP_NAME environment
	// variable to override.
	HubbleGroupName = "hubble"
	// HubbleGroupNameKey is the environment variable name to override the group for unix domain socket.
	HubbleGroupNameKey = "HUBBLE_GROUP_NAME"
	// SocketFileMode is the default file mode for the sockets.
	SocketFileMode os.FileMode = 0660
	// ClientTimeout specifies timeout to be used by clients
	ClientTimeout = 90 * time.Second

	// DefaultSocketPath which hubble listens to
	DefaultSocketPath = "unix:///var/run/hubble.sock"
	// DefaultSocketPathKey is the environment variable name to override the default socket path for
	// observe and status commands.
	DefaultSocketPathKey = "HUBBLE_DEFAULT_SOCKET_PATH"

	// ConnectionTimeout ...
	ConnectionTimeout = 12 * time.Second
)
