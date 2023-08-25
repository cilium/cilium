// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

const (
	// IPAMKubernetes is the value to select the Kubernetes PodCIDR based
	// hostscope IPAM mode
	IPAMKubernetes = "kubernetes"

	// IPAMCRD is the value to select the CRD-backed IPAM plugin for
	// option.IPAM
	IPAMCRD = "crd"

	// IPAMENI is the value to select the AWS ENI IPAM plugin for option.IPAM
	IPAMENI = "eni"

	// IPAMAzure is the value to select the Azure IPAM plugin for
	// option.IPAM
	IPAMAzure = "azure"

	// IPAMClusterPool is the value to select the cluster pool mode for
	// option.IPAM
	IPAMClusterPool = "cluster-pool"

	// IPAMClusterPoolV2 is the value to select cluster pool version 2
	IPAMClusterPoolV2 = "cluster-pool-v2beta"

	// IPAMMultiPool is the value to select the multi pool IPAM mode
	IPAMMultiPool = "multi-pool"

	// IPAMAlibabaCloud is the value to select the AlibabaCloud ENI IPAM plugin for option.IPAM
	IPAMAlibabaCloud = "alibabacloud"

	// IPAMDelegatedPlugin is the value to select CNI delegated IPAM plugin mode.
	// In this mode, Cilium CNI invokes another CNI binary (the delegated plugin) for IPAM.
	// See https://www.cni.dev/docs/spec/#section-4-plugin-delegation
	IPAMDelegatedPlugin = "delegated-plugin"
)

const (
	IPAMMarkForRelease  = "marked-for-release"
	IPAMReadyForRelease = "ready-for-release"
	IPAMDoNotRelease    = "do-not-release"
	IPAMReleased        = "released"
)

// ENIPDBlockSizeIPv4 is the number of IPs available on an ENI IPv4 prefix. Currently, AWS only supports /28 fixed size
// prefixes. Every /28 prefix contains 16 IP addresses.
// See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html#ec2-prefix-basics for more details
const ENIPDBlockSizeIPv4 = 16

// PoolDefault is the default IP pool from which to allocate.
const PoolDefault = "default"
