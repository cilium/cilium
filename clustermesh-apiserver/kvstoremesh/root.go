// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstoremesh")
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kvstoremesh",
		Short: "Run KVStoreMesh",
		Run: func(cmd *cobra.Command, args []string) {
			if err := h.Run(); err != nil {
				log.Fatal(err)
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for KVStoreMesh
			metrics.Namespace = metrics.CiliumKVStoreMeshNamespace
			option.Config.Populate(h.Viper())
			if option.Config.Debug {
				log.Logger.SetLevel(logrus.DebugLevel)
			}
			option.LogRegisteredOptions(h.Viper(), log)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())

	return rootCmd
}

func registerClusterInfoValidator(lc hive.Lifecycle, cinfo types.ClusterInfo) {
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			if err := cinfo.InitClusterIDMax(); err != nil {
				return err
			}
			if err := cinfo.ValidateStrict(); err != nil {
				return err
			}
			return nil
		},
	})
}
