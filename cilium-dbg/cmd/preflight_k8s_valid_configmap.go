// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	daemonCmd "github.com/cilium/cilium/daemon/cmd"
	operatorCmd "github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
)

func validateConfigmapCmd() *cobra.Command {
	var filename string
	cmd := &cobra.Command{
		Use:   "validate-configmap",
		Short: "Validate cilium-configmap.yaml for unrecognized keys in the daemon and operator.",
		Long: `Before upgrading Cilium, it is recommended to run this validation checker to 
ensure that the deployed Cilium ConfigMap is valid. The validator verifies that all configuration
keys are recognized by both the deamon and the operator. If any unrecognized keys are found, an
error is printed and the command exits with a non-zero status code.`,
	}

	cmd.Flags().StringVar(&filename, "filename", "", "Path to the cilium-configmap.yaml")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		validateUnrecognizedKeys(filename)

	}
	return cmd
}

func validateUnrecognizedKeys(filename string) {
	var cm corev1.ConfigMap
	dh := hive.New(daemonCmd.Agent)
	oh := hive.New(operatorCmd.Operator)
	recognizedKeys := make(map[string]struct{})

	file, err := os.Open(filename)
	if err != nil {
		Fatalf("open %q failed: %v", filename, err)
	}
	defer file.Close()

	if err := yaml.NewYAMLOrJSONDecoder(file, 4096).Decode(&cm); err != nil {
		Fatalf("decode %q failed: %v", filename, err)
	}

	daemonCmd.InitGlobalFlags(logging.DefaultSlogLogger, &cobra.Command{}, dh.Viper())
	operatorCmd.InitGlobalFlags(logging.DefaultSlogLogger, &cobra.Command{}, oh.Viper())

	for _, hook := range operatorCmd.FlagsHooks {
		hook.RegisterProviderFlag(&cobra.Command{}, oh.Viper())
	}

	for _, src := range []*viper.Viper{dh.Viper(), oh.Viper()} {
		for _, key := range src.AllKeys() {
			recognizedKeys[key] = struct{}{}
		}
	}

	var unrecognized []string
	for k := range cm.Data {
		if _, ok := recognizedKeys[k]; !ok {
			unrecognized = append(unrecognized, k)
		}
	}

	if len(unrecognized) == 0 {
		fmt.Println("All keys are recognized.")
		return
	}

	sort.Strings(unrecognized)
	fmt.Println("Warning: unrecognized keys detected:")
	for _, key := range unrecognized {
		fmt.Printf("  - %s\n", key)
	}
}
