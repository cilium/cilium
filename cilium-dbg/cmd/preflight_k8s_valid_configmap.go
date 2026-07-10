// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	daemonCmd "github.com/cilium/cilium/daemon/cmd"
	operatorCmd "github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
)

func validateConfigmapCmd() *cobra.Command {
	var configMapDir string
	cmd := &cobra.Command{
		Use:   "validate-configmap",
		Short: "Validate Cilium ConfigMap for unrecognized keys in the daemon and operator.",
		Long: `Before upgrading Cilium, it is recommended to run this validation checker to 
ensure that the deployed Cilium ConfigMap is valid. The validator verifies that all configuration
keys are recognized by both the daemon and the operator. If any unrecognized keys are found, an
error is printed and the command exits with a non-zero status code.`,
	}

	cmd.Flags().StringVar(&configMapDir, "configmap-dir", "",
		"Path to a directory mounted from a Kubernetes ConfigMap; all files in this directory will be loaded as configuration")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		if err := validateUnrecognizedKeys(configMapDir); err != nil {
			Fatalf("%s", err)
		}
	}
	return cmd
}

func validateUnrecognizedKeys(configMapDir string) error {
	var err error
	var cm map[string]any
	dh := hive.New(daemonCmd.Agent)
	oh := hive.New(operatorCmd.Operator())
	recognizedKeys := make(map[string]struct{})

	if _, err := os.Stat(configMapDir); os.IsNotExist(err) {
		return fmt.Errorf("non-existent configuration directory %s", configMapDir)
	}
	if cm, err = option.ReadDirConfig(log, configMapDir); err != nil {
		return err
	}

	daemonCmd.InitGlobalFlags(log, &cobra.Command{}, dh.Viper())
	operatorCmd.InitGlobalFlags(log, &cobra.Command{}, oh.Viper())

	for _, src := range []*viper.Viper{dh.Viper(), oh.Viper()} {
		for _, key := range src.AllKeys() {
			recognizedKeys[key] = struct{}{}
		}
	}

	var unrecognized []string
	for k := range cm {
		if _, ok := recognizedKeys[k]; !ok {
			unrecognized = append(unrecognized, k)
		}
	}

	if len(unrecognized) == 0 {
		fmt.Println("All keys are recognized.")
		return nil
	}

	sort.Strings(unrecognized)
	return fmt.Errorf(
		"unrecognized keys detected:\n  - %s",
		strings.Join(unrecognized, "\n  - "),
	)
}
