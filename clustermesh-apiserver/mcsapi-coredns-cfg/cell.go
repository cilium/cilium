// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapiCorednsCfg

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

const (
	// DefaultCoreDNSDeploymentName is the default Deployment name of CoreDNS
	DefaultCoreDNSDeploymentName = "coredns"
	// DefaultCoreDNSConfigMapName is the default ConfigMap name of CoreDNS
	DefaultCoreDNSConfigMapName = "coredns"
	// DefaultCoreDNSNamespace is the default Namespace of CoreDNS
	DefaultCoreDNSNamespace = "kube-system"
	// DefaultCoreDNSClusterDomain is the default cluster domain of CoreDNS
	DefaultCoreDNSClusterDomain = "cluster.local"
	// DefaultCoreDNSClustersetDomain is the default clusterset domain of CoreDNS
	DefaultCoreDNSClustersetDomain = "clusterset.local"
)

type coreDNSConfig struct {
	CoreDNSDeploymentName   string
	CoreDNSConfigMapName    string
	CoreDNSNamespace        string
	CoreDNSClusterDomain    string
	CoreDNSClustersetDomain string
}

func (def coreDNSConfig) Flags(flags *pflag.FlagSet) {
	flags.String("coredns-deployment-name", def.CoreDNSDeploymentName, "Deployment name of CoreDNS")
	flags.String("coredns-configmap-name", def.CoreDNSConfigMapName, "ConfigMap name of CoreDNS")
	flags.String("coredns-namespace", def.CoreDNSNamespace, "Namespace of CoreDNS")
	flags.String("coredns-cluster-domain", def.CoreDNSClusterDomain, "Cluster domain of CoreDNS")
	flags.String("coredns-clusterset-domain", def.CoreDNSClustersetDomain, "Clusterset domain of CoreDNS")
}

var Cell = cell.Module(
	"coredns-mcsapi-auto-configure",
	"CoreDNS MCS-API auto-configuration",

	k8sClient.Cell,

	cell.Config(coreDNSConfig{
		CoreDNSDeploymentName:   DefaultCoreDNSDeploymentName,
		CoreDNSConfigMapName:    DefaultCoreDNSConfigMapName,
		CoreDNSNamespace:        DefaultCoreDNSNamespace,
		CoreDNSClusterDomain:    DefaultCoreDNSClusterDomain,
		CoreDNSClustersetDomain: DefaultCoreDNSClustersetDomain,
	}),
	cell.Invoke(configureCoreDNS),
)
