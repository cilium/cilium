// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	fakeiptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
)

// mock DNS proxy for port binding tests
type startupDNSProxy struct {
	proxy.DNSProxier
	listen func(uint16) error
	port   uint16
}

func (p *startupDNSProxy) Listen(port uint16) error { return p.listen(port) }
func (p *startupDNSProxy) GetBindPort() uint16      { return p.port }
func (p *startupDNSProxy) Cleanup()                 {}

type startupIPTables struct {
	*fakeiptables.Manager
	installing chan struct{}
	resume     <-chan struct{}
}

func (p *startupIPTables) InstallProxyRules(uint16, string) {
	close(p.installing)
	<-p.resume
}

func TestDNSProxyStartupReadiness(t *testing.T) {
	listenErr := errors.New("failed to bind DNS socket")
	fallbackErr := errors.New("failed to bind DNS socket on a fresh port")

	for _, tt := range []struct {
		name         string
		disabled     bool
		dryMode      bool
		cancel       bool
		portConflict bool
		restoredPort bool
		randomPort   bool
		listenErr    error
		fallbackErr  error
		wantErr      error
	}{
		{name: "ready after port registration and acknowledgment"},
		{name: "configured port unavailable", listenErr: listenErr, wantErr: listenErr},
		{name: "restored port reused", restoredPort: true},
		{name: "restored port unavailable", restoredPort: true, listenErr: listenErr},
		{name: "fallback bind failed", restoredPort: true, listenErr: listenErr, fallbackErr: fallbackErr, wantErr: fallbackErr},
		{name: "random bind failed", randomPort: true, listenErr: listenErr, wantErr: listenErr},
		{name: "port registration conflict continues", portConflict: true},
		{name: "disabled", disabled: true},
		{name: "dry mode", dryMode: true},
		{name: "canceled", cancel: true, wantErr: context.Canceled},
	} {
		bindPort := uint16(10094)
		fallbackPort := uint16(10095)

		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t)

			original := option.Config
			option.Config = &option.DaemonConfig{
				EnableL7Proxy:    !tt.disabled,
				DryMode:          tt.dryMode,
				ToFQDNsProxyPort: int(bindPort),
				StateDir:         t.TempDir(),
			}
			if tt.restoredPort || tt.randomPort {
				// no configured port
				option.Config.ToFQDNsProxyPort = 0
			}
			t.Cleanup(func() { option.Config = original })

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			listening, resumeListen := make(chan struct{}), make(chan struct{})
			resumeRules := make(chan struct{})
			releaseListen := sync.OnceFunc(func() { close(resumeListen) })
			releaseRules := sync.OnceFunc(func() { close(resumeRules) })
			iptables := &startupIPTables{fakeiptables.NewManager(), make(chan struct{}), resumeRules}
			ports := proxyports.NewProxyPorts(log, proxyports.ProxyPortsConfig{
				ProxyPortrangeMin: 10000, ProxyPortrangeMax: 20000,
			}, iptables)
			ports.Trigger = job.NewTrigger()
			health, _ := cell.NewSimpleHealth()

			if !tt.cancel {
				// A missing state file uses the fake iptables fallback and completes restoration.
				require.Error(t, ports.RestoreProxyPorts(ctx, health))
			}
			if tt.restoredPort {
				require.NoError(t, ports.SetProxyPort(proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, bindPort, false))
			}
			if tt.portConflict {
				_, pp := ports.FindByTypeWithReference(proxytypes.ProxyTypeDNS, "", false)
				require.NotNil(t, pp)
				require.NoError(t, ports.AllocatePort(pp, false))
			}
			preferredPort := bindPort
			if tt.randomPort {
				preferredPort = 0
			}
			p := &startupDNSProxy{}
			p.listen = func(port uint16) error {
				if port == preferredPort {
					close(listening)
					<-resumeListen
					if tt.listenErr == nil {
						p.port = bindPort
					}
					return tt.listenErr
				}
				require.Zero(t, port, "fallback must request a fresh port")
				if tt.fallbackErr == nil {
					p.port = fallbackPort
				}
				return tt.fallbackErr
			}
			var ready promise.Promise[DNSProxyInitialized]
			h := hive.New(
				job.Cell,
				cell.Provide(func(reg job.Registry) job.Group { return reg.NewGroup(health) }),
				cell.Provide(func() (*proxyports.ProxyPorts, proxy.DNSProxier, messagehandler.DNSMessageHandler) {
					return ports, p, messagehandler.NewDNSMessageHandler(messagehandler.DNSMessageHandlerParams{Logger: log})
				}),
				cell.Provide(newFQDNProxyBootstrapper),
				cell.Invoke(func(in struct {
					cell.In
					Ready     promise.Promise[DNSProxyInitialized]
					Notifiers []endpointstate.RestorationNotifier `group:"endpointRestorationNotifiers"`
				}) {
					ready = in.Ready
					for _, notifier := range in.Notifiers {
						if notifier != nil {
							notifier.RestorationNotify(nil)
						}
					}
				}),
			)
			t.Cleanup(func() {
				releaseListen()
				releaseRules()
				require.NoError(t, h.Stop(log, context.Background()))
			})
			require.NoError(t, h.Start(log, ctx))

			if tt.cancel {
				require.NoError(t, h.Stop(log, ctx))
			} else if !tt.disabled && !tt.dryMode {
				select {
				case <-listening:
					// listen called with port == preferredPort
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}

				// 1st Await call times out since socket binding is blocked on
				// resumeListen channel
				waitCtx, stop := context.WithTimeout(ctx, 10*time.Millisecond)
				_, err := ready.Await(waitCtx)
				stop()
				require.ErrorIs(t, err, context.DeadlineExceeded, "readiness must wait for socket binding")
				releaseListen() // let listen continue

				if tt.wantErr == nil {
					select {
					case <-iptables.installing:
						// iptables rules installation started
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}

					// 2nd Await call times out since iptables rules install is
					// blocked on resumeRules channel
					waitCtx, stop := context.WithTimeout(ctx, 10*time.Millisecond)
					_, err := ready.Await(waitCtx)
					stop()
					require.ErrorIs(t, err, context.DeadlineExceeded, "readiness must wait for datapath acknowledgment")
					releaseRules() // let iptables install continue
				}
			}

			// DNS proxy must get ready at this point, unless tt.wantErr != nil
			_, err := ready.Await(ctx)
			require.ErrorIs(t, err, tt.wantErr)

			if tt.disabled || tt.dryMode || tt.wantErr != nil || tt.portConflict {
				return
			}

			port, isStatic, err := ports.GetProxyPort(proxytypes.DNSProxyName)
			require.NoError(t, err)
			require.Equal(t, p.port, port)
			require.True(t, isStatic)

			_, redirect := ports.FindByTypeWithReference(proxytypes.ProxyTypeDNS, "", false)
			require.NoError(t, ports.AllocatePort(redirect, false))
			require.Equal(t, p.port, redirect.ProxyPort, "DNS redirects must use the bound socket port")
			require.Equal(t, p.port, ports.GetRulesPort(redirect))
		})
	}
}
