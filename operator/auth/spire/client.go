// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/auth/identity"
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
	cell.Config(ClientConfig{}),
	cell.Provide(NewClient),
)

var FakeCellClient = cell.Module(
	"fake-spire-client",
	"Fake Spire Server API Client",
	cell.Config(ClientConfig{}),
	cell.Provide(NewFakeClient),
)

// ClientConfig contains the configuration for the SPIRE client.
type ClientConfig struct {
	MutualAuthEnabled            bool          `mapstructure:"mesh-auth-mutual-enabled"`
	SpireAgentSocketPath         string        `mapstructure:"mesh-auth-spire-agent-socket"`
	SpireServerAddress           string        `mapstructure:"mesh-auth-spire-server-address"`
	SpireServerConnectionTimeout time.Duration `mapstructure:"mesh-auth-spire-server-connection-timeout"`
	SpiffeTrustDomain            string        `mapstructure:"mesh-auth-spiffe-trust-domain"`
}

// Flags adds the flags used by ClientConfig.
func (cfg ClientConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&cfg.MutualAuthEnabled,
		"mesh-auth-mutual-enabled",
		false,
		"The flag to enable mutual authentication for the SPIRE server (beta).")
	flags.StringVar(&cfg.SpireAgentSocketPath,
		"mesh-auth-spire-agent-socket",
		"/run/spire/sockets/agent/agent.sock",
		"The path for the SPIRE admin agent Unix socket.")
	flags.StringVar(&cfg.SpireServerAddress,
		"mesh-auth-spire-server-address",
		"spire-server.spire.svc:8081",
		"SPIRE server endpoint.")
	flags.DurationVar(&cfg.SpireServerConnectionTimeout,
		"mesh-auth-spire-server-connection-timeout",
		10*time.Second,
		"SPIRE server connection timeout.")
	flags.StringVar(&cfg.SpiffeTrustDomain,
		"mesh-auth-spiffe-trust-domain",
		"spiffe.cilium",
		"The trust domain for the SPIFFE identity.")
}

type params struct {
	cell.In

	K8sClient k8sClient.Clientset
}

type Client struct {
	cfg        ClientConfig
	log        logrus.FieldLogger
	entry      entryv1.EntryClient
	entryMutex lock.RWMutex
	k8sClient  k8sClient.Clientset
}

// NewClient creates a new SPIRE client.
// If the mutual authentication is not enabled, it returns a noop client.
func NewClient(params params, lc cell.Lifecycle, cfg ClientConfig, log logrus.FieldLogger) identity.Provider {
	if !cfg.MutualAuthEnabled {
		return &noopClient{}
	}
	client := &Client{
		k8sClient: params.K8sClient,
		cfg:       cfg,
		log:       log.WithField(logfields.LogSubsys, "spire-client"),
	}

	lc.Append(cell.Hook{
		OnStart: client.onStart,
		OnStop:  func(_ cell.HookContext) error { return nil },
	})
	return client
}

func (c *Client) onStart(_ cell.HookContext) error {
	go func() {
		c.log.Info("Initializing SPIRE client")
		attempts := 0
		backoffTime := backoff.Exponential{Min: 100 * time.Millisecond, Max: 10 * time.Second}
		for {
			attempts++
			conn, err := c.connect(context.Background())
			if err == nil {
				c.entryMutex.Lock()
				c.entry = entryv1.NewEntryClient(conn)
				c.entryMutex.Unlock()
				break
			}
			c.log.WithError(err).Warnf("Unable to connect to SPIRE server, attempt %d", attempts+1)
			time.Sleep(backoffTime.Duration(attempts))
		}
		c.log.Info("Initialized SPIRE client")
	}()
	return nil
}

func (c *Client) connect(ctx context.Context) (*grpc.ClientConn, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, c.cfg.SpireServerConnectionTimeout)
	defer cancelFunc()

	resolvedTarget, err := resolvedK8sService(ctx, c.k8sClient, c.cfg.SpireServerAddress)
	if err != nil {
		c.log.WithError(err).
			WithField(logfields.URL, c.cfg.SpireServerAddress).
			Warning("Unable to resolve SPIRE server address, using original value")
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

	c.log.WithFields(logrus.Fields{
		logfields.Address: c.cfg.SpireServerAddress,
		logfields.IPAddr:  resolvedTarget,
	}).Info("Trying to connect to SPIRE server")
	conn, err := grpc.Dial(*resolvedTarget, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection to SPIRE server: %w", err)
	}

	c.log.WithFields(logrus.Fields{
		logfields.Address: c.cfg.SpireServerAddress,
		logfields.IPAddr:  resolvedTarget,
	}).Info("Connected to SPIRE server")
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

func (c *Client) List(ctx context.Context) ([]string, error) {
	c.entryMutex.RLock()
	defer c.entryMutex.RUnlock()
	entries, err := c.entry.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
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
