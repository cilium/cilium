// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package node

import (
	"log/slog"
)

func initLocalBootID(_ *slog.Logger) {}
