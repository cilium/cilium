package client

import (
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

type Config struct {
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

func (cfg Config) CellFlags(flags *pflag.FlagSet) {
	flags.String(option.K8sAPIServer, "", "Kubernetes API server URL")
	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	flags.Float32(option.K8sClientQPSLimit, defaults.K8sClientQPSLimit, "Queries per second limit for the K8s client")
	flags.Int(option.K8sClientBurst, defaults.K8sClientBurst, "Burst value allowed for the K8s client")
	flags.Duration(option.K8sHeartbeatTimeout, 30*time.Second, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	flags.Bool(option.K8sEnableAPIDiscovery, defaults.K8sEnableAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
}

// K8sAPIDiscoveryEnabled returns true if API discovery of API groups and
// resources is enabled
func (cfg Config) K8sAPIDiscoveryEnabled() bool {
	return cfg.EnableK8sAPIDiscovery
}

// K8sLeasesFallbackDiscoveryEnabled returns true if we should fallback to direct API
// probing when checking for support of Leases in case Discovery API fails to discover
// required groups.
func (cfg Config) K8sLeasesFallbackDiscoveryEnabled() bool {
	return cfg.K8sAPIDiscoveryEnabled()
}

func (cfg Config) isEnabled() bool {
	return cfg.K8sAPIServer != "" ||
		cfg.K8sKubeConfigPath != "" ||
		(os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
			os.Getenv("KUBERNETES_SERVICE_PORT") != "") ||
		os.Getenv("K8S_NODE_NAME") != ""
}
