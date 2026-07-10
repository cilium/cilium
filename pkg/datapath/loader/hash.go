// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/config"
	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
)

// datapathHash represents a unique enumeration of the datapath configuration.
type datapathHash []byte

// hashDatapath returns a new datapath hash based on the specified datapath.
func hashDatapath(c linuxConfig.Writer, nodeCfg *config.Config) (datapathHash, error) {
	d := sha256.New()
	err := c.WriteNodeConfig(d, nodeCfg)
	if err != nil {
		return nil, err
	}
	return datapathHash(d.Sum(nil)), nil
}

func (d datapathHash) hashEndpoint(c linuxConfig.Writer, nodeCfg *config.Config, epCfg endpoint.Config) (string, error) {
	h := sha256.New()
	_, _ = h.Write(d)
	if err := c.WriteEndpointConfig(h, epCfg); err != nil {
		return "", err
	}

	// Include endpoint configuration in the hash, otherwise different runtime
	// configurations will hash to the same value and the update will be skipped.
	if epCfg.IsHost() {
		for _, cfg := range ciliumHostConfiguration(epCfg, nodeCfg) {
			if _, err := fmt.Fprintf(h, "%+v", cfg); err != nil {
				return "", fmt.Errorf("hashing host configuration: %w", err)
			}
		}
	} else {
		for _, cfg := range endpointConfiguration(epCfg, nodeCfg) {
			if _, err := fmt.Fprintf(h, "%+v", cfg); err != nil {
				return "", fmt.Errorf("hashing endpoint runtime configuration: %w", err)
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d datapathHash) hashTemplate(c linuxConfig.Writer, epCfg endpoint.Config) (string, error) {
	h := sha256.New()
	_, _ = h.Write(d)
	if err := c.WriteTemplateConfig(h, epCfg); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d datapathHash) String() string {
	return hex.EncodeToString(d)
}
