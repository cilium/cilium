// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
)

type (
	RevNatKey   = maps.RevNatKey
	RevNatValue = maps.RevNatValue

	ServiceKey   = maps.ServiceKey
	ServiceValue = maps.ServiceValue

	Backend      = maps.Backend
	BackendKey   = maps.BackendKey
	BackendValue = maps.BackendValue
)
