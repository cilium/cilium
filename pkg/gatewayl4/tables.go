// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gatewayl4

import (
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// GatewayL4Config is the agent model of CiliumGatewayL4Config.
// Stored in the 'ciliumgatewayl4configs' table for inspection.
type GatewayL4Config struct {
	Name   k8sTypes.NamespacedName
	Labels map[string]string
	Spec   *ciliumv2alpha1.CiliumGatewayL4ConfigSpec
}

func (cfg *GatewayL4Config) Clone() *GatewayL4Config {
	cfg2 := *cfg
	return &cfg2
}

func (*GatewayL4Config) TableHeader() []string {
	return []string{
		"Name",
		"Gateway",
		"Listeners",
		"Backends",
	}
}

func (cfg *GatewayL4Config) TableRow() []string {
	var (
		gatewayRef string
		listeners  []string
		backends   int
	)

	if cfg.Spec != nil {
		gatewayRef = cfg.Spec.GatewayRef.Name
		if cfg.Spec.GatewayRef.Namespace != "" {
			gatewayRef = cfg.Spec.GatewayRef.Namespace + "/" + gatewayRef
		}

		for _, l := range cfg.Spec.Listeners {
			listeners = append(listeners, l.Name+"/"+string(l.Protocol)+":"+strconv.Itoa(int(l.Port)))
			backends += len(l.Backends)
		}
	}

	slices.Sort(listeners)

	return []string{
		cfg.Name.String(),
		gatewayRef,
		strings.Join(listeners, ", "),
		strconv.Itoa(backends),
	}
}

type GatewayL4ConfigName = k8sTypes.NamespacedName

const (
	GatewayL4TableName = "ciliumgatewayl4configs"
)

var (
	gatewayL4NameIndex = statedb.Index[*GatewayL4Config, GatewayL4ConfigName]{
		Name: "name",
		FromObject: func(obj *GatewayL4Config) index.KeySet {
			return index.NewKeySet(index.String(obj.Name.String()))
		},
		FromKey: index.Stringer[k8sTypes.NamespacedName],
		Unique:  true,
	}

	GatewayL4ByName = gatewayL4NameIndex.Query
)

func NewGatewayL4Table(db *statedb.DB) (statedb.RWTable[*GatewayL4Config], error) {
	return statedb.NewTable(
		db,
		GatewayL4TableName,
		gatewayL4NameIndex,
	)
}
