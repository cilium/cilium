// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"crypto/sha256"
	"encoding/hex"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// datapathHash represents a unique enumeration of the datapath configuration.
type datapathHash []byte

// hashDatapath returns a new datapath hash based on the specified datapath.
func hashDatapath(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration) (datapathHash, error) {
	d := sha256.New()
	err := c.WriteNodeConfig(d, nodeCfg)
	if err != nil {
		return nil, err
	}
	return datapathHash(d.Sum(nil)), nil
}

func (d datapathHash) hashEndpoint(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration, epCfg datapath.EndpointConfiguration) (string, error) {
	h := sha256.New()
	_, _ = h.Write(d)
	if err := c.WriteEndpointConfig(h, nodeCfg, epCfg); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d datapathHash) hashTemplate(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration, epCfg datapath.EndpointConfiguration) (string, error) {
	h := sha256.New()
	_, _ = h.Write(d)
	if err := c.WriteTemplateConfig(h, nodeCfg, epCfg); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d datapathHash) String() string {
	return hex.EncodeToString(d)
}
