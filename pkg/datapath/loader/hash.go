// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"hash"
	"io"

	"github.com/cilium/cilium/pkg/datapath"
)

var (
	// DatapathSHA256 is set during build to the SHA across all datapath BPF
	// code. See the definition of CILIUM_DATAPATH_SHA256 in Makefile.defs for
	// details.
	DatapathSHA256 string
)

// datapathHash represents a unique enumeration of the datapath implementation.
type datapathHash struct {
	hash.Hash
}

// newDatapathHash creates a new datapath hash based on the contents of the datapath
// template files under bpf/.
func newDatapathHash() *datapathHash {
	d := sha256.New()
	io.WriteString(d, DatapathSHA256)
	return &datapathHash{
		Hash: d,
	}
}

// hashDatapath returns a new datapath hash based on the specified datapath.
//
// The endpoint's static data is NOT included in this hash, for that perform:
//	hash := hashDatapath(dp, nodeCfg, netdevCfg, ep)
//	hashStr := hash.sumEndpoint(ep)
func hashDatapath(c datapath.ConfigWriter, nodeCfg *datapath.LocalNodeConfiguration, netdevCfg datapath.DeviceConfiguration, epCfg datapath.EndpointConfiguration) *datapathHash {
	d := newDatapathHash()

	// Writes won't fail; it's an in-memory hash.
	if nodeCfg != nil {
		_ = c.WriteNodeConfig(d, nodeCfg)
	}
	if netdevCfg != nil {
		_ = c.WriteNetdevConfig(d, netdevCfg)
	}
	if epCfg != nil {
		_ = c.WriteTemplateConfig(d, epCfg)
	}

	return d
}

// sumEndpoint returns the hash of the complete datapath for an endpoint.
// It does not change the underlying hash state.
func (d *datapathHash) sumEndpoint(c datapath.ConfigWriter, epCfg datapath.EndpointConfiguration, staticData bool) (string, error) {
	result, err := d.Copy()
	if err != nil {
		return "", err
	}
	if staticData {
		c.WriteEndpointConfig(result, epCfg)
	} else {
		c.WriteTemplateConfig(result, epCfg)
	}
	return result.String(), nil
}

func (d *datapathHash) Copy() (*datapathHash, error) {
	state, err := d.Hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}
	newDatapathHash := sha256.New()
	if err := newDatapathHash.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return nil, err
	}
	return &datapathHash{
		Hash: newDatapathHash,
	}, nil
}

func (d *datapathHash) String() string {
	return hex.EncodeToString(d.Sum(nil))
}
