package services

import (
	"testing"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/test/control-plane/services"
)

func TestMain(m *testing.M) {
	services.TestMain(m)
}

func TestDualStack(t *testing.T) {
	testCase := services.NewGoldenTest(t, "dual-stack")

	// FIXME remove use of testing.T from within validation
	testCase.Steps[0].AddValidation(func(lbmap *mockmaps.LBMockMap) error {
		assert := lbmapAssert{t, lbmap}

		// Verify that default/echo-dualstack service exists
		// for both NodePort and ClusterIP, and that it has backends
		// for udp:69, and tcp:80 for both IPv4 and IPv6.
		assert.servicesExist(
			"default/echo-dualstack",
			[]lb.SVCType{lb.SVCTypeNodePort, lb.SVCTypeClusterIP},
			[]svcL3Type{svcIPv4, svcIPv6},
			lb.UDP,
			69)
		assert.servicesExist(
			"default/echo-dualstack",
			[]lb.SVCType{lb.SVCTypeNodePort, lb.SVCTypeClusterIP},
			[]svcL3Type{svcIPv4, svcIPv6},
			lb.TCP,
			80)

		return nil
	})

	modConfig := func(c *option.DaemonConfig) {
		c.EnableIPv6 = true
		c.EnableNodePort = true
	}
	testCase.Run(t, modConfig)
}

//
// LBMap assertions
//

type svcL3Type string

const (
	svcIPv4 = svcL3Type("IPv4")
	svcIPv6 = svcL3Type("IPV6")
)

type lbmapAssert struct {
	t     *testing.T
	lbmap *mockmaps.LBMockMap
}

// findService finds a service matching the parameters and that it has a
// backend with specified l4 type and port.
//
// Linear in time, but should be OK for tests with few 10s of services
// and backends.
func (a lbmapAssert) findServiceWithBackend(name string, svcType lb.SVCType, l3 svcL3Type, l4 lb.L4Type, port uint16) *lb.SVC {
	for _, svc := range a.lbmap.ServiceByID {
		svcL3Type := svcIPv4
		if svc.Frontend.IsIPv6() {
			svcL3Type = svcIPv6
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
// TODO: this does too much. break up service and backend assertions?
func (a lbmapAssert) servicesExist(name string, svcTypes []lb.SVCType, l3s []svcL3Type, l4 lb.L4Type, port uint16) {
	for _, svcType := range svcTypes {
		for _, l3 := range l3s {
			if svc := a.findServiceWithBackend(name, svcType, l3, l4, port); svc == nil {
				a.t.Fatalf("Service for name=%q, type=%q, l3=%q, l4=%q, port=%d not found", name, svcType, l3, l4, port)
			}
		}
	}
}
