// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

//
// LBMap assertions
//

type SVCL3Type string

const (
	SVCIPv4 = SVCL3Type("IPv4")
	SVCIPv6 = SVCL3Type("IPV6")
)

type LBMapAssert struct {
	lbmap *mockmaps.LBMockMap
}

func NewLBMapAssert(lbmap *mockmaps.LBMockMap) LBMapAssert {
	return LBMapAssert{lbmap}
}

// findService finds a service matching the parameters and that it has a
// backend with specified l4 type and port.
//
// Linear in time, but should be OK for tests with few 10s of services
// and backends.
func (a LBMapAssert) FindServiceWithBackend(name string, svcType lb.SVCType, l3 SVCL3Type, l4 lb.L4Type, port uint16) *lb.SVC {
	for _, svc := range a.lbmap.ServiceByID {
		svcL3Type := SVCIPv4
		if svc.Frontend.IsIPv6() {
			svcL3Type = SVCIPv6
		}
		match := svc.Type == svcType
		match = match && l3 == svcL3Type
		l4match := false
		for _, be := range svc.Backends {
			if l4 == be.L4Addr.Protocol && be.L4Addr.Port == port {
				l4match = true
				break
			}
		}
		match = match && l4match
		if match {
			return svc
		}
	}
	return nil
}

// servicesExist asserts that the service with given name (<namespace>/<name>) exists for
// the listed service types and has frontends with the given L3 protocols, and that
// it has backend with the given L4 type and port.
func (a LBMapAssert) ServicesExist(name string, svcTypes []lb.SVCType, l3s []SVCL3Type, l4 lb.L4Type, port uint16) error {
	for _, svcType := range svcTypes {
		for _, l3 := range l3s {
			if svc := a.FindServiceWithBackend(name, svcType, l3, l4, port); svc == nil {
				return fmt.Errorf("Service for name=%q, type=%q, l3=%q, l4=%q, port=%d not found", name, svcType, l3, l4, port)
			}
		}
	}
	return nil
}
