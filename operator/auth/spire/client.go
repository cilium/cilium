// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cilium/cilium/operator/auth/identity"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
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
		Value: "mtls",
	},
}

// Cell is the cell for the SPIRE client.
var Cell = cell.Module(
	"spire-client",
	"Spire Server API Client",
	cell.Config(ClientConfig{}),
	cell.Provide(NewClient),
)

// ClientConfig contains the configuration for the SPIRE client.
type ClientConfig struct {
	AuthMTLSEnabled              bool          `mapstructure:"mesh-auth-mtls-enabled"`
	SpireAgentSocketPath         string        `mapstructure:"mesh-auth-spire-agent-socket"`
	SpireServerAddress           string        `mapstructure:"mesh-auth-spire-server-address"`
	SpireServerConnectionTimeout time.Duration `mapstructure:"mesh-auth-spire-server-connection-timeout"`
	SpiffeTrustDomain            string        `mapstructure:"mesh-auth-spiffe-trust-domain"`
}

// Flags adds the flags used by ClientConfig.
func (cfg ClientConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&cfg.AuthMTLSEnabled,
		"mesh-auth-mtls-enabled",
		false,
		"The flag to enable mTLS for the SPIRE server.")
	flags.StringVar(&cfg.SpireAgentSocketPath,
		"mesh-auth-spire-agent-socket",
		"/run/spire/sockets/agent/agent.sock",
		"The path for the SPIRE admin agent Unix socket.")
	flags.StringVar(&cfg.SpireServerAddress,
		"mesh-auth-spire-server-address",
		"spire-server.spire.svc.cluster.local:8081",
		"SPIRE server endpoint.")
	flags.DurationVar(&cfg.SpireServerConnectionTimeout,
		"mesh-auth-spire-server-connection-timeout",
		10*time.Second,
		"SPIRE server endpoint.")
	flags.StringVar(&cfg.SpiffeTrustDomain,
		"mesh-auth-spiffe-trust-domain",
		"spiffe.cilium",
		"The trust domain for the SPIFFE identity.")
}

type Client struct {
	cfg   ClientConfig
	log   logrus.FieldLogger
	entry entryv1.EntryClient
}

// NewClient creates a new SPIRE client.
// If the mTLS is not enabled, it returns a noop client.
func NewClient(lc hive.Lifecycle, cfg ClientConfig, log logrus.FieldLogger) identity.Provider {
	if !cfg.AuthMTLSEnabled {
		return &noopClient{}
	}
	client := &Client{
		cfg: cfg,
		log: log.WithField(logfields.LogSubsys, "spire-client"),
	}

	lc.Append(hive.Hook{
		OnStart: client.onStart,
		OnStop:  func(_ hive.HookContext) error { return nil },
	})
	return client
}

func (c *Client) onStart(_ hive.HookContext) error {
	go func() {
		c.log.Info("Initializing SPIRE client")
		attempts := 0
		backoffTime := backoff.Exponential{Min: 100 * time.Millisecond, Max: 10 * time.Second}
		for {
			attempts++
			conn, err := c.connect(context.Background())
			if err == nil {
				c.entry = entryv1.NewEntryClient(conn)
				break
			}
			c.log.WithError(err).Errorf("Unable to connect to SPIRE server, attempt %d", attempts+1)
			time.Sleep(backoffTime.Duration(attempts))
		}
		c.log.Info("Initialized SPIRE client")
	}()
	return nil
}

func (c *Client) connect(ctx context.Context) (*grpc.ClientConn, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, c.cfg.SpireServerConnectionTimeout)
	defer cancelFunc()

	// This is blocking till the cilium-operator is registered in SPIRE.
	source, err := workloadapi.NewX509Source(timeoutCtx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(fmt.Sprintf("unix://%s", c.cfg.SpireAgentSocketPath)),
			workloadapi.WithLogger(c.log),
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
	conn, err := grpc.Dial(c.cfg.SpireServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection to SPIRE server: %w", err)
	}

	return conn, nil
}

// Upsert creates or updates the SPIFFE ID for the given ID.
// The SPIFFE ID is in the form of spiffe://<trust-domain>/identity/<id>.
func (c *Client) Upsert(ctx context.Context, id string) error {
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
				Path:        toPath(id),
			},
			ParentId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        defaultParentID,
			},
			Selectors: defaultSelectors,
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

// Delete deletes the SPIFFE ID for the given ID.
// The SPIFFE ID is in the form of spiffe://<trust-domain>/identity/<id>.
func (c *Client) Delete(ctx context.Context, id string) error {
	if c.entry == nil {
		return fmt.Errorf("unable to connect to SPIRE server %s", c.cfg.SpireServerAddress)
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

// listEntries returns the list of entries for the given ID.
// The maximum number of entries returned is 1, so page token can be ignored.
func (c *Client) listEntries(ctx context.Context, id string) (*entryv1.ListEntriesResponse, error) {
	return c.entry.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			BySpiffeId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        toPath(id),
			},
			ByParentId: &types.SPIFFEID{
				TrustDomain: c.cfg.SpiffeTrustDomain,
				Path:        defaultParentID,
			},
			BySelectors: &types.SelectorMatch{
				Selectors: defaultSelectors,
				Match:     types.SelectorMatch_MATCH_EXACT,
			},
		},
	})
}

func toPath(id string) string {
	return fmt.Sprintf("%s/%s", pathPrefix, id)
}
