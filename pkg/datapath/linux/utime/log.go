// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utime

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	subsystem = "utime"
	log       = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, subsystem))
)
