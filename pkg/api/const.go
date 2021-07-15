// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2020 Authors of Cilium

package api

import (
	"os"
	"time"
)

const (
	// CiliumGroupName is the cilium's unix group name.
	CiliumGroupName = "cilium"
	// SocketFileMode is the default file mode for the sockets.
	SocketFileMode os.FileMode = 0660
	// ClientTimeout specifies timeout to be used by clients
	ClientTimeout = 90 * time.Second
)
