// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

const OptUserAgent = "user-agent"

type Config struct {
	// EnableK8s is a flag that, when set to false, forcibly disables the clientset, to let cilium
	// operates with CNI-compatible orchestrators other than Kubernetes. Default to true.
	EnableK8s bool

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer string

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath string

	// K8sClientQPS is the queries per second limit for the K8s client. Defaults to k8s client defaults.
	K8sClientQPS float32

	// K8sClientBurst is the burst value allowed for the K8s client. Defaults to k8s client defaults.
	K8sClientBurst int

	// K8sHeartbeatTimeout configures the timeout for apiserver heartbeat
	K8sHeartbeatTimeout time.Duration

	// K8sEnableAPIDiscovery enables Kubernetes API discovery
	EnableK8sAPIDiscovery bool
}

var defaultConfig = Config{
	EnableK8s:             true,
	K8sAPIServer:          "",
	K8sKubeConfigPath:     "",
	K8sClientQPS:          defaults.K8sClientQPSLimit,
	K8sClientBurst:        defaults.K8sClientBurst,
	K8sHeartbeatTimeout:   30 * time.Second,
	EnableK8sAPIDiscovery: defaults.K8sEnableAPIDiscovery,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableK8s, def.EnableK8s, "Enable the k8s clientset")
	flags.String(option.K8sAPIServer, def.K8sAPIServer, "Kubernetes API server URL")
	flags.String(option.K8sKubeConfigPath, def.K8sKubeConfigPath, "Absolute path of the kubernetes kubeconfig file")
	flags.Float32(option.K8sClientQPSLimit, def.K8sClientQPS, "Queries per second limit for the K8s client")
	flags.Int(option.K8sClientBurst, def.K8sClientBurst, "Burst value allowed for the K8s client")
	flags.Duration(option.K8sHeartbeatTimeout, def.K8sHeartbeatTimeout, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	flags.Bool(option.K8sEnableAPIDiscovery, def.EnableK8sAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
}

func (cfg Config) isEnabled() bool {
	if !cfg.EnableK8s {
		return false
	}
	return cfg.K8sAPIServer != "" ||
		cfg.K8sKubeConfigPath != "" ||
		(os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
			os.Getenv("KUBERNETES_SERVICE_PORT") != "") ||
		os.Getenv("K8S_NODE_NAME") != ""
}
