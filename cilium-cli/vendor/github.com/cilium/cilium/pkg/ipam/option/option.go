// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

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

	// IPAMAlibabaCloud is the value to select the AlibabaCloud ENI IPAM plugin for option.IPAM
	IPAMAlibabaCloud = "alibabacloud"
)
