// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	subsystem = "policymap"
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)
)
