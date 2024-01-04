// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func Test_filterServiceBackends(t *testing.T) {
	t.Run("filter by port number", func(t *testing.T) {
		svc := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Port: 8080,
					},
				},
			},
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 3000,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends["*"], 1)
		})
		t.Run("only http port", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"8080"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["8080"], 1)
		})
		t.Run("no match", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"8000"})
			assert.Len(t, backends, 0)
		})
	})

	t.Run("filter by port named", func(t *testing.T) {
		svc := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Port: 8000,
					},
				},
			},
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8080,
						},
					},
				},
				{
					FEPortName: "https",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8443,
						},
					},
				},
				{
					FEPortName: "metrics",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8081,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends["*"], 3)
		})
		t.Run("only http named port", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["http"], 1)
		})
		t.Run("multiple named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http", "metrics"})
			assert.Len(t, backends, 2)

			assert.Len(t, backends["http"], 1)
			assert.Equal(t, (int)(backends["http"][0].Port), 8080)

			assert.Len(t, backends["metrics"], 1)
			assert.Equal(t, (int)(backends["metrics"][0].Port), 8081)
		})
	})

	t.Run("filter with preferred backend", func(t *testing.T) {
		svc := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Port: 8000,
					},
				},
			},
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8080,
						},
					},
					Preferred: loadbalancer.Preferred(true),
				},
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8081,
						},
					},
				},
				{
					FEPortName: "https",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 443,
						},
					},
				},
				{
					FEPortName: "80",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8080,
						},
					},
					Preferred: loadbalancer.Preferred(true),
				},
				{
					FEPortName: "80",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8081,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends["*"], 2)
		})

		t.Run("only named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["http"], 1)
		})
		t.Run("multiple named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http", "https"})
			assert.Len(t, backends, 1)

			assert.Len(t, backends["http"], 1)
			assert.Equal(t, (int)(backends["http"][0].Port), 8080)
		})

		t.Run("only port number", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"80"})
			assert.Len(t, backends, 1)

			assert.Len(t, backends["80"], 1)
			assert.Equal(t, (int)(backends["80"][0].Port), 8080)
		})
	})
}
