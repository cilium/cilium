// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"log/slog"

	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
)

// Endpoint provides access endpoint configuration information that is necessary
// to compile and load the datapath.
type Endpoint interface {
	endpoint.Config
	InterfaceName() string
	Logger(subsystem string) *slog.Logger
	StateDir() string
}
