// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package ebpf

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ebpf")
)
