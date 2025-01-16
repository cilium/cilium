// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, "clustermesh"))

const (
	fieldClusterName = "clusterName"
	fieldConfig      = "config"
	fieldConfigDir   = "configDir"
	fieldEvent       = "event"
)
