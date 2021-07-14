// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package store

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "node")
