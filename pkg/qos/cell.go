// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qos

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/qos/config"
)

// Cell provides the configuration of the QoS API.
var Cell = cell.Module(
	"qos",
	"Network Quality of Service",

	cell.Config(config.DefaultConfig),
)
