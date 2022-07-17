// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bigtcp

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "big-tcp")
