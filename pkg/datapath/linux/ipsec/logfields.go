// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package ipsec

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipsec")
