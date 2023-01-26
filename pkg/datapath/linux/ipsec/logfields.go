// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var subsystem = metric.Subsystem{
	Name:    "ipsec",
	DocName: "IPSec",
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem.Name)
