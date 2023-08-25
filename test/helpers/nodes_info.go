// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"
	"strings"
)

type NodesInfo struct {
	K8s1NodeName      string
	K8s2NodeName      string
	OutsideNodeName   string
	K8s1IP            string
	K8s2IP            string
	OutsideIP         string
	PrivateIface      string
	PrimaryK8s1IPv6   string
	PrimaryK8s2IPv6   string
	OutsideIPv6       string
	SecondaryK8s1IPv4 string
	SecondaryK8s2IPv4 string
	SecondaryK8s1IPv6 string
	SecondaryK8s2IPv6 string
}

func GetNodesInfo(kubectl *Kubectl) (*NodesInfo, error) {
	var (
		ni  NodesInfo
		err error
	)

	ni.K8s1NodeName, ni.K8s1IP = kubectl.GetNodeInfo(K8s1)
	ni.K8s2NodeName, ni.K8s2IP = kubectl.GetNodeInfo(K8s2)
	if ExistNodeWithoutCilium() {
		ni.OutsideNodeName, ni.OutsideIP = kubectl.GetNodeInfo(kubectl.GetFirstNodeWithoutCiliumLabel())
	}

	ni.PrivateIface, err = kubectl.GetPrivateIface(K8s1)
	if err != nil {
		return nil, fmt.Errorf("Cannot determine private iface: %w", err)
	}

	if GetCurrentIntegration() == "" || IsIntegration(CIIntegrationKind) {
		ni.PrimaryK8s1IPv6, err = GetIPv6AddrForIface(kubectl, ni.K8s1NodeName, ni.PrivateIface)
		if err != nil {
			return nil, err
		}
		ni.PrimaryK8s2IPv6, err = GetIPv6AddrForIface(kubectl, ni.K8s2NodeName, ni.PrivateIface)
		if err != nil {
			return nil, err
		}

		// If there is no integration we assume that these are running in vagrant environment
		// so have a Secondary interface with both IPv6 and IPv4 addresses.
		ni.SecondaryK8s1IPv4, err = GetIPv4AddrForIface(kubectl, ni.K8s1NodeName, SecondaryIface)
		if err != nil {
			return nil, err
		}
		ni.SecondaryK8s2IPv4, err = GetIPv4AddrForIface(kubectl, ni.K8s2NodeName, SecondaryIface)
		if err != nil {
			return nil, err
		}

		ni.SecondaryK8s1IPv6, err = GetIPv6AddrForIface(kubectl, ni.K8s1NodeName, SecondaryIface)
		if err != nil {
			return nil, err
		}
		ni.SecondaryK8s2IPv6, err = GetIPv6AddrForIface(kubectl, ni.K8s2NodeName, SecondaryIface)
		if err != nil {
			return nil, err
		}

		if ExistNodeWithoutCilium() {
			ni.OutsideIPv6, err = GetIPv6AddrForIface(kubectl, ni.OutsideNodeName, ni.PrivateIface)
			if err != nil {
				return nil, err
			}
		}
	}

	return &ni, nil
}

func GetIPv4AddrForIface(kubectl *Kubectl, nodeName, iface string) (string, error) {
	cmd := fmt.Sprintf("ip -family inet -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)
	res := kubectl.ExecInHostNetNS(context.TODO(), nodeName, cmd)
	if err := res.GetError(); err != nil {
		return "", fmt.Errorf("Cannot get IPv4 address for interface(%q): %w",
			iface, err)
	}
	ipv4 := strings.Trim(res.Stdout(), "\n")
	return ipv4, nil
}

func GetIPv6AddrForIface(kubectl *Kubectl, nodeName, iface string) (string, error) {
	cmd := fmt.Sprintf("ip -family inet6 -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)
	res := kubectl.ExecInHostNetNS(context.TODO(), nodeName, cmd)
	if err := res.GetError(); err != nil {
		return "", fmt.Errorf("Cannot get IPv6 address for interface(%q): %w",
			iface, err)
	}
	ipv6 := strings.Trim(res.Stdout(), "\n")
	return ipv6, nil
}
