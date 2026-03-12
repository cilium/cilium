// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"log/slog"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

const (
	DPPTableName = "datapathplugins"
)

var pluginNameIndex = statedb.Index[*api_v2alpha1.CiliumDatapathPlugin, string]{
	Name: "name",
	FromObject: func(obj *api_v2alpha1.CiliumDatapathPlugin) index.KeySet {
		return index.NewKeySet(index.String(obj.Name))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

func NewDPPTable(db *statedb.DB) (statedb.RWTable[*api_v2alpha1.CiliumDatapathPlugin], error) {
	return statedb.NewTableAny(
		db,
		DPPTableName,
		dppTableHeader,
		dppTableRow,
		pluginNameIndex,
	)
}

func dppTableHeader() []string {
	return []string{"Name", "Attachment Policy", "Version"}
}

func dppTableRow(dp *api_v2alpha1.CiliumDatapathPlugin) []string {
	return []string{dp.Name, string(dp.Spec.AttachmentPolicy), dp.Spec.Version}
}

type dppListerWatcher cache.ListerWatcher

func newDPPListerWatcher(cs client.Clientset, config datapathPluginsConfig) dppListerWatcher {
	if !cs.IsEnabled() || !option.Config.EnableDatapathPlugins {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumDatapathPlugins())
}

func registerDPPReflector(db *statedb.DB, log *slog.Logger, jg job.Group, lw dppListerWatcher, dpps statedb.RWTable[*api_v2alpha1.CiliumDatapathPlugin], config datapathPluginsConfig) error {
	if !option.Config.EnableDatapathPlugins || lw == nil {
		return nil
	}

	return k8s.RegisterReflector(
		jg,
		db,
		k8s.ReflectorConfig[*api_v2alpha1.CiliumDatapathPlugin]{
			Name:          "dpps",
			Table:         dpps,
			ListerWatcher: lw,
			MetricScope:   "CiliumDatapathPlugin",
		},
	)
}
