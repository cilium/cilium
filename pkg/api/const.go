// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"os"
	"time"
)

const (
	// SocketFileMode is the default file mode for the sockets.
	SocketFileMode os.FileMode = 0660
	// ClientTimeout specifies timeout to be used by clients
	ClientTimeout = 90 * time.Second
)
