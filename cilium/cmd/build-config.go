// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sConsts "github.com/cilium/cilium/pkg/k8s/constants"
	"github.com/cilium/cilium/pkg/option/resolver"
)

var buildConfigCell = cell.Module(
	"build-config",
	"Configuration resolver",
	cell.Config(defaultBuildConfigCfg),
	cell.Provide(newBuildConfig),
)

var buildConfigHive = hive.New(
	k8sClient.Cell,
	buildConfigCell,
	cell.Invoke(func(*buildConfig) {}),
)

// configCmd represents the config command
var buildConfigCmd = &cobra.Command{
	Use:   "build-config --node-name $K8S_NODE_NAME",
	Short: "Resolve all of the configuration sources that apply to this node",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Running")
		return buildConfigHive.Run()
	},
}

func init() {
	buildConfigHive.RegisterFlags(buildConfigCmd.Flags())
	rootCmd.AddCommand(buildConfigCmd)
}

type buildConfigCfg struct {
	Dest     string
	NodeName string

	Source []string

	AllowConfigKeys []string
	DenyConfigKeys  []string
}

func (bcc buildConfigCfg) Flags(flags *pflag.FlagSet) {
	flags.String("dest", bcc.Dest, "Destination directory to write the fully-resolved configuration.")
	flags.String("node-name", bcc.NodeName, "The name of the node on which we are running. Also set via K8S_NODE_NAME environment.")
	flags.StringSlice("source", bcc.Source, "Ordered list of configuration sources. "+
		"Supported values: config-map:<namespace>/name - a ConfigMap with <name>, optionally in namespace <namespace>. "+
		"cilium-node-config:<NAMESPACE> - any CiliumNodeConfigs in namespace <NAMESPACE>.  node:<NODENAME> - Annotations on the node. Namespace and nodename are optional")
	flags.StringSlice("allow-config-keys", bcc.AllowConfigKeys, "List of configuration keys that are allowed to be overridden (e.g. set from not the first source. Takes precedence over deny-config-keys")
	flags.StringSlice("deny-config-keys", bcc.DenyConfigKeys, "List of configuration keys that are not allowed to be overridden (e.g. set from not the first source. If allow-config-keys is set, this field is ignored")
}

// defaultExampleConfig is the defaults for the configuration.
var defaultBuildConfigCfg = buildConfigCfg{
	Dest:     "/tmp/cilium/config-map",
	NodeName: os.Getenv(k8sConsts.EnvNodeNameSpec),

	Source: []string{
		resolver.KindConfigMap + ":cilium-config",
		resolver.KindNodeConfig + ":" + os.Getenv("CILIUM_K8S_NAMESPACE"),
	},
}

type buildConfig struct {
	cfg        buildConfigCfg
	log        logrus.FieldLogger
	client     k8sClient.Clientset
	shutdowner hive.Shutdowner
}

func newBuildConfig(lc hive.Lifecycle, cfg buildConfigCfg, log logrus.FieldLogger, client k8sClient.Clientset, shutdowner hive.Shutdowner) (*buildConfig, error) {
	if cfg.Dest == "" {
		return nil, fmt.Errorf("--dest is required")
	}

	obj := &buildConfig{
		cfg:        cfg,
		log:        log,
		client:     client,
		shutdowner: shutdowner,
	}

	lc.Append(hive.Hook{OnStart: obj.onStart})

	return obj, nil
}

func (bc *buildConfig) onStart(ctx hive.HookContext) error {
	sources := []resolver.ConfigSource{}
	for _, sourceSpec := range bc.cfg.Source {
		if sourceSpec == "" {
			continue
		}
		parsed := strings.SplitN(sourceSpec, ":", 2)
		if len(parsed) == 0 {
			continue
		}
		source := resolver.ConfigSource{
			Kind: parsed[0],
		}

		// Fill in any defaults if the source spec is not supplied
		switch source.Kind {
		case resolver.KindConfigMap:
			source.Name = "cilium-config"
			source.Namespace = os.Getenv("CILIUM_K8S_NAMESPACE")
		case resolver.KindNodeConfig:
			source.Namespace = os.Getenv("CILIUM_K8S_NAMESPACE")
		case resolver.KindNode:
			source.Name = os.Getenv(k8sConsts.EnvNodeNameSpec)
		default:
			return fmt.Errorf("unknown config source %s", source.Kind)
		}

		// Parse the source-spec (e.g. namespace, name)
		if len(parsed) == 2 && len(parsed[1]) > 0 {
			parsed := strings.SplitN(parsed[1], "/", 2)
			if len(parsed) == 1 {
				switch source.Kind {
				case resolver.KindConfigMap:
					source.Name = parsed[0]
					source.Namespace = os.Getenv("CILIUM_K8S_NAMESPACE")
				case resolver.KindNodeConfig:
					source.Namespace = parsed[0]
				case resolver.KindNode:
					source.Name = parsed[0]
				}
			} else if len(parsed) == 2 {
				source.Namespace = parsed[0]
				source.Name = parsed[1]
			}
		}
		sources = append(sources, source)
	}

	config, err := resolver.ResolveConfigurations(ctx, bc.client, bc.cfg.NodeName, sources, bc.cfg.AllowConfigKeys, bc.cfg.DenyConfigKeys)
	if err != nil {
		return fmt.Errorf("failed to resolve configurations: %w", err)
	}

	if err := os.MkdirAll(bc.cfg.Dest, 0777); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", bc.cfg.Dest, err)
	}

	if err := resolver.WriteConfigurations(ctx, bc.cfg.Dest, config); err != nil {
		return fmt.Errorf("failed to write configurations to %s: %w", bc.cfg.Dest, err)
	}

	bc.shutdowner.Shutdown()
	return nil
}
