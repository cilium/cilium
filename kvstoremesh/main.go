// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	kmmetrics "github.com/cilium/cilium/kvstoremesh/metrics"
	kmopt "github.com/cilium/cilium/kvstoremesh/option"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstoremesh")

	rootHive *hive.Hive

	rootCmd = &cobra.Command{
		Use:   "kvstoremesh",
		Short: "Run KVStoreMesh",
		Run: func(cmd *cobra.Command, args []string) {
			if err := rootHive.Run(); err != nil {
				log.Fatal(err)
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for KVStoreMesh
			metrics.Namespace = metrics.CiliumKVStoreMeshNamespace
			option.Config.Populate(rootHive.Viper())
			if option.Config.Debug {
				log.Logger.SetLevel(logrus.DebugLevel)
			}
			option.LogRegisteredOptions(rootHive.Viper(), log)
		},
	}
)

func init() {
	rootHive = hive.New(
		pprof.Cell,
		cell.Config(pprof.Config{
			PprofAddress: kmopt.PprofAddress,
			PprofPort:    kmopt.PprofPort,
		}),
		controller.Cell,

		gops.Cell(defaults.GopsPortKVStoreMesh),
		kmmetrics.Cell,

		cell.Config(kmopt.KVStoreMeshConfig{}),
		cell.Provide(cfgAdapter),

		kvstore.Cell(kvstore.EtcdBackendName),
		cell.Provide(func() *kvstore.ExtraOptions { return nil }),
		kvstoremesh.Cell,

		cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
	)

	rootHive.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(rootHive.Command())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cfgAdapter(lc hive.Lifecycle, cfg kmopt.KVStoreMeshConfig) (types.ClusterIDName, error) {
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			if err := types.ValidateClusterID(cfg.ClusterID); err != nil {
				return err
			}

			if cfg.ClusterName == "" {
				return errors.New("ClusterName is unset")
			}

			return nil
		},
	})

	return types.ClusterIDName{
		ClusterID:   cfg.ClusterID,
		ClusterName: cfg.ClusterName,
	}, nil
}
