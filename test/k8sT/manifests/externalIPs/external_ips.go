// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package external_ips

const (
	PublicInterfaceName  = "enp0s10"
	PrivateInterfaceName = "enp0s8"
)

// On both dev and CI VMs the public interface, i.e., an interface that has a
// network shared with the host is the 'enp0s10'. The private interface, i.e.,
// an interface that has a network shared with all VMs is the 'enp0s8'
var NetDevTranslation = map[string]string{
	"svc-a-external-ips-k8s1-host-public":  PublicInterfaceName,
	"svc-b-external-ips-k8s1-host-public":  PublicInterfaceName,
	"svc-a-external-ips-k8s1-host-private": PrivateInterfaceName,
	"svc-b-external-ips-k8s1-host-private": PrivateInterfaceName,
}

type EntryTestArgs struct {
	Description string
	Expected    string
	IP          string
	Port        string
	SkipReason  string
}
