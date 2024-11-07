// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import appsv1 "k8s.io/api/apps/v1"

const (
	// SocatServerPort is the port on which the socat server listens.
	socatServerDaemonsetName  = "socat-server-daemonset"
	socatClientDeploymentName = "socat-client"
)

func NewSocatServerDaemonSet(params Parameters) *appsv1.DaemonSet {
	ds := newDaemonSet(daemonSetParameters{
		Name:    socatServerDaemonsetName,
		Kind:    socatServerDaemonsetName,
		Image:   params.SocatImage,
		Command: []string{"/bin/sh", "-c", "sleep 10000000"},
	})
	return ds
}

func NewSocatClientDeployment(params Parameters) *appsv1.Deployment {
	dep := newDeployment(deploymentParameters{
		Name:     socatClientDeploymentName,
		Kind:     socatClientDeploymentName,
		Image:    params.SocatImage,
		Replicas: 1,
		Command:  []string{"/bin/sh", "-c", "sleep 10000000"},
	})
	return dep
}
