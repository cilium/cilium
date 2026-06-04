// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/cni/libcni"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// NetConf is the Cilium specific CNI network configuration
type NetConf struct {
	cniTypes.NetConf
	MTU            int                    `json:"mtu"`
	Args           Args                   `json:"args"`
	EnableRouteMTU bool                   `json:"enable-route-mtu"`
	ENI            eniTypes.ENISpec       `json:"eni,omitempty"`
	Azure          azureTypes.AzureSpec   `json:"azure,omitempty"`
	IPAM           IPAM                   `json:"ipam,omitempty"` // Shadows the JSON field "ipam" in cniTypes.NetConf.
	AlibabaCloud   alibabaCloudTypes.Spec `json:"alibaba-cloud,omitempty"`
	EnableDebug    bool                   `json:"enable-debug"`
	LogFormat      string                 `json:"log-format"`
	LogFile        string                 `json:"log-file"`
	ChainingMode   string                 `json:"chaining-mode"`

	// PluginConfig holds the cilium-cni plugin block, with name and cniVersion
	// injected from the conflist envelope, parsed by libcni. It is the complete
	// plugin configuration handed to a delegated IPAM plugin's stdin, preserving
	// plugin-specific fields not modeled by NetConf.
	PluginConfig *libcni.PluginConfig `json:"-"`
}

// IPAM is the Cilium specific CNI IPAM configuration
type IPAM struct {
	cniTypes.IPAM
	ipamTypes.IPAMSpec
}

// NetConfList is a CNI chaining configuration
type NetConfList struct {
	Plugins []*NetConf `json:"plugins,omitempty"`
}

func parsePrevResult(n *NetConf) (*NetConf, error) {
	if n.RawPrevResult != nil {
		resultBytes, err := json.Marshal(n.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %w", err)
		}
		res, err := version.NewResult(n.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %w", err)
		}
		n.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %w", err)
		}
	}

	return n, nil
}

// ReadNetConf reads a CNI configuration file and returns the corresponding
// NetConf structure
// For conflists, NetConf.PluginConfig is populated best-effort for delegated IPAM use.
func ReadNetConf(path string) (*NetConf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read CNI configuration '%s': %w", path, err)
	}

	netConfList := &NetConfList{}
	if err := json.Unmarshal(b, netConfList); err == nil {
		for _, plugin := range netConfList.Plugins {
			if plugin.Type == "cilium-cni" {
				// Best-effort: capture libcni plugin block bytes for delegated IPAM,
				// with conflist name and cniVersion injected.
				if confList, err := libcni.NetworkConfFromBytes(b); err == nil {
					for _, p := range confList.Plugins {
						if p.Network == nil || p.Network.Type != "cilium-cni" {
							continue
						}
						// InjectConf takes the cilium-cni plugin block as libcni parsed it from
						// the conflist and returns a new *libcni.PluginConfig whose .Bytes are
						// the original plugin block with name and cniVersion merged in. That is
						// the shape a CNI IPAM plugin expects on stdin.
						ipamInput, err := libcni.InjectConf(p, map[string]any{
							"name":       confList.Name,
							"cniVersion": confList.CNIVersion,
						})
						if err != nil {
							return nil, fmt.Errorf("failed to inject name/cniVersion into cilium-cni plugin block of conflist %q: %w", path, err)
						}
						plugin.PluginConfig = ipamInput
						break
					}
				}
				return parsePrevResult(plugin)
			}
		}
	}

	return LoadNetConf(b)
}

// LoadNetConf unmarshals a Cilium network configuration from JSON and returns
// a NetConf together with the CNI version
func LoadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %w", err)
	}

	return parsePrevResult(n)
}

// ArgsSpec is the specification of additional arguments of the CNI ADD call
type ArgsSpec struct {
	cniTypes.CommonArgs
	K8S_POD_NAME      cniTypes.UnmarshallableString
	K8S_POD_NAMESPACE cniTypes.UnmarshallableString
	K8S_POD_UID       cniTypes.UnmarshallableString
}

// Args contains arbitrary information a scheduler
// can pass to the cni plugin
type Args struct{}

// CNI error codes
// (error codes 100+ are allowed for plugin use)
const (
	CniErrHealthzGet uint = 100 + iota
	CniErrUnhealthy
)
const CniErrPluginNotAvailable uint = 50
