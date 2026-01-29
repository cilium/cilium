// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/auth/identity"
	ztunnel "github.com/cilium/cilium/operator/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/backoff"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	notFoundError   = "NotFound"
	defaultParentID = "/cilium-operator"
	pathPrefix      = "/identity"
)

var defaultSelectors = []*types.Selector{
	{
		Type:  "cilium",
		Value: "mutual-auth",
	},
}

// Cell is the cell for the SPIRE client.
var Cell = cell.Module(
	"spire-client",
	"Spire Server API Client",
	cell.Config(defaultMutualAuthConfig),
	cell.Config(defaultClientConfig),
	cell.Provide(func(zfg ztunnel.Config) SpireEntryConfig {
		if zfg.EnableZTunnel {
			return SpireEntryConfig{
				ParentID:      "/ztunnel",
				PathFunc:      ztunnel.SpiffeIDPathFunc,
				SelectorsFunc: ztunnel.SpiffeIDSelectorsFunc,
			}
		}
		return SpireEntryConfig{
			ParentID:      defaultParentID,
			PathFunc:      toPath,
			SelectorsFunc: func(id string) []*types.Selector { return defaultSelectors },
		}
	}),
	cell.Provide(NewClient),
)

var FakeCellClient = cell.Module(
	"fake-spire-client",
	"Fake Spire Server API Client",
	cell.Config(defaultMutualAuthConfig),
	cell.Config(defaultClientConfig),
	cell.Provide(NewFakeClient),
)

// MutualAuthConfig contains general configuration for mutual authentication.
type MutualAuthConfig struct {
	Enabled bool `mapstructure:"mesh-auth-mutual-enabled"`
}

var defaultMutualAuthConfig = MutualAuthConfig{
	Enabled: false,
}

// Flags adds the flags used by ClientConfig.
func (cfg MutualAuthConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("mesh-auth-mutual-enabled",
		cfg.Enabled,
		"The flag to enable mutual authentication for the SPIRE server (beta).")
}

// ClientConfig contains the configuration for the SPIRE client.
type ClientConfig struct {
	SpireAgentSocketPath         string        `mapstructure:"mesh-auth-spire-agent-socket"`
	SpireServerAddress           string        `mapstructure:"mesh-auth-spire-server-address"`
	SpireServerConnectionTimeout time.Duration `mapstructure:"mesh-auth-spire-server-connection-timeout"`
	SpiffeTrustDomain            string        `mapstructure:"mesh-auth-spiffe-trust-domain"`
}

var defaultClientConfig = ClientConfig{
	SpireAgentSocketPath:         "/run/spire/sockets/agent/agent.sock",
	SpireServerAddress:           "spire-server.spire.svc:8081",
	SpireServerConnectionTimeout: 10 * time.Second,
	SpiffeTrustDomain:            "spiffe.cilium",
}

// Flags adds the flags used by ClientConfig.
func (cfg ClientConfig) Flags(flags *pflag.FlagSet) {
	flags.String("mesh-auth-spire-agent-socket",
		cfg.SpireAgentSocketPath,
		"The path for the SPIRE admin agent Unix socket.")
	flags.String("mesh-auth-spire-server-address",
		cfg.SpireServerAddress,
		"SPIRE server endpoint.")
	flags.Duration("mesh-auth-spire-server-connection-timeout",
		cfg.SpireServerConnectionTimeout,
		"SPIRE server connection timeout.")
	flags.String("mesh-auth-spiffe-trust-domain",
		cfg.SpiffeTrustDomain,
		"The trust domain for the SPIFFE identity.")
}

type params struct {
	cell.In

	Logger           *slog.Logger
	K8sClient        k8sClient.Clientset
	Lifecycle        cell.Lifecycle
	MutualAuthConfig MutualAuthConfig
	ClientConfig     ClientConfig
	EntryConfig      SpireEntryConfig
	ZtunnelConfig    ztunnel.Config
}

type Client struct {
	cfg         ClientConfig
	log         *slog.Logger
	entry       entryv1.EntryClient
	entryCfg    SpireEntryConfig
	entryMutex  lock.RWMutex
	k8sClient   k8sClient.Clientset
	initialized chan struct{}
}

type SpireEntryConfig struct {
	ParentID      string
	PathFunc      func(string) string
	SelectorsFunc func(string) []*types.Selector
}

type out struct {
	cell.Out

	Provider identity.Provider
	Client   *Client
}

// NewClient creates a new SPIRE client.
// If the mutual authentication is not enabled, it returns a noop client.
func NewClient(params params) out {
	if !params.MutualAuthConfig.Enabled {
		return out{
			Provider: &noopClient{},
			Client:   nil,
		}
	}

	client := &Client{
		k8sClient:   params.K8sClient,
		cfg:         params.ClientConfig,
		entryCfg:    params.EntryConfig,
		log:         params.Logger.With(logfields.LogSubsys, "spire-client"),
		initialized: make(chan struct{}),
	}

	var provider identity.Provider = client
	if params.ZtunnelConfig.EnableZTunnel {
		params.Logger.Info("Ztunnel-Spire integration enabled, returning noop identity provider")
		provider = &noopClient{}
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: client.onStart,
		OnStop:  func(_ cell.HookContext) error { return nil },
	})
	return out{
		Provider: provider,
		Client:   client,
	}
}

func (c *Client) GetSpireEntryConfig() SpireEntryConfig {
	return c.entryCfg
}

func (c *Client) GetSpireTrustDomain() string {
	return c.cfg.SpiffeTrustDomain
}

// Initialized returns a channel that is closed when the client is initialized.
func (c *Client) Initialized() <-chan struct{} {
	return c.initialized
}

func (c *Client) onStart(ctx cell.HookContext) error {
	go func() {
		c.log.InfoContext(ctx, "Initializing SPIRE client")
		attempts := 0
		backoffTime := backoff.Exponential{Logger: c.log, Min: 100 * time.Millisecond, Max: 10 * time.Second}
		for {
			attempts++
			conn, err := c.connect(context.Background())
			if err == nil {
				c.entryMutex.Lock()
				c.entry = entryv1.NewEntryClient(conn)
				c.entryMutex.Unlock()
				close(c.initialized)
				break
			}
			c.log.WarnContext(ctx,
				"Unable to connect to SPIRE server",
				logfields.Attempt, attempts+1,
				logfields.Error, err)
			time.Sleep(backoffTime.Duration(attempts))
		}
		c.log.InfoContext(ctx, "Initialized SPIRE client")
	}()
	return nil
}

func (c *Client) connect(ctx context.Context) (*grpc.ClientConn, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, c.cfg.SpireServerConnectionTimeout)
	defer cancelFunc()

	resolvedTarget, err := resolvedK8sService(ctx, c.k8sClient, c.cfg.SpireServerAddress)
	if err != nil {
		c.log.WarnContext(ctx,
			"Unable to resolve SPIRE server address, using original value",
			logfields.Error, err,
			logfields.URL, c.cfg.SpireServerAddress)
		resolvedTarget = &c.cfg.SpireServerAddress
	}

	// This is blocking till the cilium-operator is registered in SPIRE.
	source, err := workloadapi.NewX509Source(timeoutCtx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(fmt.Sprintf("unix://%s", c.cfg.SpireAgentSocketPath)),
			workloadapi.WithLogger(newSpiffeLogWrapper(c.log)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509 source: %w", err)
	}

	trustedDomain, err := spiffeid.TrustDomainFromString(c.cfg.SpiffeTrustDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain: %w", err)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(trustedDomain))

	c.log.InfoContext(ctx,
		"Trying to connect to SPIRE server",
		logfields.Address, c.cfg.SpireServerAddress,
		logfields.IPAddr, resolvedTarget)
	conn, err := grpc.NewClient(*resolvedTarget, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection to SPIRE server: %w", err)
	}

	c.log.InfoContext(ctx,
		"Connected to SPIRE server",
		logfields.Address, c.cfg.SpireServerAddress,
		logfields.IPAddr, resolvedTarget)
	return conn, nil
}

// Upsert creates or updates the SPIFFE ID for the given ID.
// The SPIFFE ID is in the form of spiffe://<trust-domain>/identity/<id>.
func (c *Client) Upsert(ctx context.Context, id string) error {
	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	if c.entry == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.cfg.SpireServerAddress)
	}

	entries, err := c.listEntries(ctx, id)
	if err != nil && !strings.Contains(err.Error(), notFoundError) {
		return err
	}

	desired := []*types.Entry{
		{
			SpiffeId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        c.entryCfg.PathFunc(id),
			},
			ParentId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        c.entryCfg.ParentID,
			},
			Selectors: c.entryCfg.SelectorsFunc(id),
		},
	}

	if entries == nil || len(entries.Entries) == 0 {
		_, err = c.entry.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{Entries: desired})
		return err
	}

	_, err = c.entry.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{
		Entries: desired,
	})
	return err
}

func (c *Client) InsertBatch(ctx context.Context, entries []*types.Entry) error {
	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()

	if c.entry == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.cfg.SpireServerAddress)
	}

	if len(entries) == 0 {
		return nil
	}

	// Try to create all entries
	resp, err := c.entry.BatchCreateEntry(ctx,
		&entryv1.BatchCreateEntryRequest{Entries: entries},
	)
	if err != nil {
		return fmt.Errorf("batch create failed: %w", err)
	}

	// Ignore AlreadyExists errors
	for _, r := range resp.Results {
		if r.Status.Code != int32(codes.OK) &&
			r.Status.Code != int32(codes.AlreadyExists) {
			return fmt.Errorf("entry create failed: %v: %s",
				r.Status.Code, r.Status.Message)
		}
	}

	return nil
}

// Delete deletes the SPIFFE ID for the given ID.
// The SPIFFE ID is in the form of spiffe://<trust-domain>/identity/<id>.
func (c *Client) Delete(ctx context.Context, id string) error {
	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	if c.entry == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.cfg.SpireServerAddress)
	}

	if len(id) == 0 {
		return nil
	}

	entries, err := c.listEntries(ctx, id)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return nil
		}
		return err
	}
	if len(entries.Entries) == 0 {
		return nil
	}
	var ids = make([]string, 0, len(entries.Entries))
	for _, e := range entries.Entries {
		ids = append(ids, e.Id)
	}

	_, err = c.entry.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{
		Ids: ids,
	})

	return err
}

// DeleteBatch deletes the SPIFFE IDs for the given list of IDs.
// The SPIFFE ID is in the form of spiffe://<trust-domain>/identity/<id>.
func (c *Client) DeleteBatch(ctx context.Context, ids []string) error {
	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	if c.entry == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.cfg.SpireServerAddress)
	}

	if len(ids) == 0 {
		return nil
	}

	// First, look up the entry IDs for all the SPIFFE IDs
	var entryIDs []string
	for _, id := range ids {
		entries, err := c.listEntries(ctx, id)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				// Entry doesn't exist, skip it
				continue
			}
			return fmt.Errorf("failed to list entries for %s: %w", id, err)
		}
		for _, e := range entries.Entries {
			entryIDs = append(entryIDs, e.Id)
		}
	}

	if len(entryIDs) == 0 {
		// All entries were already deleted
		return nil
	}

	resp, err := c.entry.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{
		Ids: entryIDs,
	})
	if err != nil {
		return fmt.Errorf("batch delete failed: %w", err)
	}

	// Ignore NotFound errors
	for _, r := range resp.Results {
		if r.Status.Code != int32(codes.OK) &&
			r.Status.Code != int32(codes.NotFound) {
			return fmt.Errorf("entry delete failed: %v: %s",
				r.Status.Code, r.Status.Message)
		}
	}

	return nil
}

func (c *Client) List(ctx context.Context) ([]string, error) {
	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	entries, err := c.entry.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			ByParentId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        c.entryCfg.ParentID,
			},
			BySelectors: &types.SelectorMatch{
				Selectors: c.entryCfg.SelectorsFunc(""),
				Match:     types.SelectorMatch_MATCH_EXACT,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(entries.Entries) == 0 {
		return nil, nil
	}
	var ids = make([]string, 0, len(entries.Entries))
	for _, e := range entries.Entries {
		ids = append(ids, e.Id)
	}
	return ids, nil
}

// listEntries returns the list of entries for the given ID.
// The maximum number of entries returned is 1, so page token can be ignored.
func (c *Client) listEntries(ctx context.Context, id string) (*entryv1.ListEntriesResponse, error) {
	return c.entry.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			BySpiffeId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        c.entryCfg.PathFunc(id),
			},
			ByParentId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        c.entryCfg.ParentID,
			},
			BySelectors: &types.SelectorMatch{
				Selectors: c.entryCfg.SelectorsFunc(id),
				Match:     types.SelectorMatch_MATCH_EXACT,
			},
		},
	})
}

// resolvedK8sService resolves the given address to the IP address.
// The input must be in the form of <service-name>.<namespace>.svc.*:<port-number>,
// otherwise the original address is returned.
func resolvedK8sService(ctx context.Context, client k8sClient.Clientset, address string) (*string, error) {
	names := strings.Split(address, ".")
	if len(names) < 3 || !strings.HasPrefix(names[2], "svc") {
		return &address, nil
	}

	// retrieve the service and return its ClusterIP
	svc, err := client.CoreV1().Services(names[1]).Get(ctx, names[0], metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	res := net.JoinHostPort(svc.Spec.ClusterIP, port)
	return &res, nil
}

func toPath(id string) string {
	return fmt.Sprintf("%s/%s", pathPrefix, id)
}
