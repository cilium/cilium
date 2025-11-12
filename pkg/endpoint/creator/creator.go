// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/lumberjack/v2"
	"go4.org/netipx"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	fqdnrules "github.com/cilium/cilium/pkg/fqdn/rules"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/time"
)

var launchTime = 30 * time.Second

type EndpointCreator interface {
	// NewEndpointFromChangeModel creates a new endpoint from a request
	NewEndpointFromChangeModel(ctx context.Context, base *models.EndpointChangeRequest) (*endpoint.Endpoint, error)

	ParseEndpoint(epJSON []byte) (*endpoint.Endpoint, error)

	// AddIngressEndpoint creates an Endpoint representing Cilium Ingress on this node without a
	// corresponding container necessarily existing. This is needed to be able to ingest and
	// sync network policies applicable to Cilium Ingress to Envoy.
	AddIngressEndpoint(ctx context.Context) error

	AddHostEndpoint(ctx context.Context) error
}

type endpointCreator struct {
	params       endpointManagerParams
	epParams     endpoint.EndpointParams
	policyLogger func() *lumberjack.Logger
}

var _ EndpointCreator = &endpointCreator{}

type endpointManagerParams struct {
	cell.In

	EndpointManager endpointmanager.EndpointManager
	DNSRulesService fqdnrules.DNSRulesService
	Proxy           *proxy.Proxy
	LocalNodeStore  *node.LocalNodeStore
	LxcMap          lxcmap.Map
}

func newEndpointCreator(p endpointManagerParams, epParams endpoint.EndpointParams) EndpointCreator {
	return &endpointCreator{
		params:       p,
		epParams:     epParams,
		policyLogger: sync.OnceValue(policyDebugLogger),
	}
}

func policyDebugLogger() *lumberjack.Logger {
	maxSize := 10 // 10 MB
	if ms := os.Getenv("CILIUM_DBG_POLICY_LOG_MAX_SIZE"); ms != "" {
		if ms, err := strconv.Atoi(ms); err == nil {
			maxSize = ms
		}
	}
	maxBackups := 3
	if mb := os.Getenv("CILIUM_DBG_POLICY_LOG_MAX_BACKUPS"); mb != "" {
		if mb, err := strconv.Atoi(mb); err == nil {
			maxBackups = mb
		}
	}
	return &lumberjack.Logger{
		Filename:   filepath.Join(option.Config.StateDir, "endpoint-policy.log"),
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     28, // days
		LocalTime:  true,
		Compress:   true,
	}
}

func (c *endpointCreator) NewEndpointFromChangeModel(ctx context.Context, base *models.EndpointChangeRequest) (*endpoint.Endpoint, error) {
	return endpoint.NewEndpointFromChangeModel(
		ctx,
		c.epParams,
		c.params.DNSRulesService,
		c.params.Proxy,
		base,
		c.policyLogger())
}

func (c *endpointCreator) ParseEndpoint(epJSON []byte) (*endpoint.Endpoint, error) {
	return endpoint.ParseEndpoint(
		c.epParams,
		c.params.DNSRulesService,
		c.params.Proxy, epJSON)
}

func (c *endpointCreator) AddIngressEndpoint(ctx context.Context) error {
	ln, err := c.params.LocalNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	// Node.IPv4IngressIP has been parsed with net.ParseIP() and may be in IPv4 mapped IPv6
	// address format. Use netipx.FromStdIP() to make sure we get a plain IPv4 address.
	ingressIPv4, _ := netipx.FromStdIP(ln.IPv4IngressIP)
	ingressIPv6, _ := netip.AddrFromSlice(ln.IPv6IngressIP)

	ep, err := endpoint.CreateIngressEndpoint(
		c.epParams,
		c.params.DNSRulesService,
		c.params.Proxy,
		c.policyLogger(),
		ingressIPv4,
		ingressIPv6,
	)
	if err != nil {
		return err
	}

	if err := c.params.EndpointManager.AddEndpoint(ep); err != nil {
		return err
	}

	ep.InitWithIngressLabels(ctx, launchTime)

	return nil
}

func (c *endpointCreator) AddHostEndpoint(ctx context.Context) error {
	ep, err := endpoint.CreateHostEndpoint(
		c.epParams,
		c.params.DNSRulesService,
		c.params.Proxy,
		c.policyLogger(),
	)
	if err != nil {
		return err
	}

	if err := c.params.EndpointManager.AddEndpoint(ep); err != nil {
		return err
	}

	node.SetEndpointID(ep.GetID())

	c.params.EndpointManager.InitHostEndpointLabels(ctx)

	return nil
}
