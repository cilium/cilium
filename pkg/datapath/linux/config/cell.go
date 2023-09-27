// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type configWriterParams struct {
	cell.In

	Log                logrus.FieldLogger
	NodeExtraDefines   []dpdef.Map `group:"header-node-defines"`
	NodeExtraDefineFns []dpdef.Fn  `group:"header-node-define-fns"`
	BandwidthManager   bandwidth.Manager
}

var Cell = cell.Module(
	"datapath-linux-config",
	"Generate and write the configuration for datapath program types",

	cell.Provide(NewHeaderfileWriter),
)
