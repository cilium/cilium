// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package init

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	einit "github.com/cilium/cilium/pkg/etcd/init"
	"github.com/cilium/cilium/pkg/etcd/init/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

const (
	keyEtcdDataDirectory           = "etcd-data-dir"
	keyEtcdClusterName             = "etcd-cluster-name"
	keyEtcdListenClientURLs        = "etcd-listen-client-urls"
	keyEtcdAdvertiseClientURLs     = "etcd-advertise-client-urls"
	keyEtcdInitialClusterToken     = "etcd-initial-cluster-token"
	keyEtcdInitialClusterState     = "etcd-initial-cluster-state"
	keyEtcdAutoCompactionRetention = "etcd-auto-compaction-retention"
	keyIPv6                        = "ipv6"
	keyForceWipeEtcdData           = "force-wipe-etcd-data"
	keyPprof                       = "pprof"
	keyPprofAddress                = "pprof-address"
	keyPprofPort                   = "pprof-port"
	keyGops                        = "gops"
	keyGopsPort                    = "gops-port"
	keyStartupTimeout              = "startup-timeout"
)

// New creates a new serve command.
func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialise an etcd server for Cilium",
		Long:  "Initialise an etcd server for Cilium",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit(vp)
		},
	}
	flags := cmd.Flags()
	flags.String(
		keyEtcdDataDirectory,
		defaults.EtcdDataDirectory,
		"Path to the etcd data directory")
	flags.String(
		keyEtcdClusterName,
		defaults.EtcdClusterName,
		"Name of the current cluster")
	flags.Bool(
		keyPprof, false, "Enable serving the pprof debugging API",
	)
	flags.Bool(
		keyIPv6, defaults.IPv6, "Use IPv6 addressing for loopback. Only needed on an IPv6 only host.",
	)
	flags.Bool(
		keyForceWipeEtcdData, false, "Wipe the given etcd data directory before starting",
	)
	flags.String(
		keyPprofAddress, defaults.PprofAddress, "Address that pprof listens on",
	)
	flags.Int(
		keyPprofPort, defaults.PprofPort, "Port that pprof listens on",
	)
	flags.Bool(
		keyGops, true, "Run gops agent",
	)
	flags.Int(
		keyGopsPort,
		defaults.GopsPort,
		"Port for gops server to listen on")
	flags.Duration(
		keyStartupTimeout,
		defaults.StartupTimeout,
		"Startup timeout for embedded etcd")
	err := vp.BindPFlags(flags)
	if err != nil {
		os.Exit(-1)
	}

	return cmd
}

func runInit(vp *viper.Viper) error {
	if vp.GetBool("debug") {
		logging.SetLogLevelToDebug()
	}
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "etcd-init")

	etcdDataDirectory := vp.GetString(keyEtcdDataDirectory)
	if vp.GetBool(keyForceWipeEtcdData) {
		logger.Debugf("Deleting directory %s", etcdDataDirectory)
		err := os.RemoveAll(etcdDataDirectory + "/*")
		if err != nil {
			return err
		}
	}

	rawPeerURL := "http://127.0.0.1:2380"
	if vp.GetBool(keyIPv6) {
		rawPeerURL = "http://[::1]:2380"
	}
	peerURL, err := url.Parse(rawPeerURL)
	if err != nil {
		return err
	}

	rawClientURL := "http://127.0.0.1:2379"
	if vp.GetBool(keyIPv6) {
		rawClientURL = "http://[::1]:2379"
	}
	clientURL, err := url.Parse(rawClientURL)
	if err != nil {
		return err
	}

	// Configure embedded etcd
	clusterName := vp.GetString(keyEtcdClusterName)
	cfg := embed.NewConfig()
	cfg.Dir = etcdDataDirectory
	cfg.Name = clusterName
	cfg.ClusterState = embed.ClusterStateFlagNew
	cfg.InitialCluster = fmt.Sprintf("%s=%s", clusterName, peerURL)
	cfg.InitialClusterToken = clusterName
	cfg.AdvertisePeerUrls = []url.URL{*peerURL}
	cfg.ListenPeerUrls = []url.URL{*peerURL}
	cfg.AdvertiseClientUrls = []url.URL{*clientURL}
	cfg.ListenClientUrls = []url.URL{*clientURL}

	// Launch server and wait for it to become ready
	logger.Debug("Starting etcd")
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return err
	}
	defer e.Close()
	logger.Debug("Waiting on ready notify")
	select {
	case <-e.Server.ReadyNotify():
		logger.Debug("Embedded etcd server has started")
	case <-time.After(60 * time.Second):
		e.Server.Stop() // trigger a shutdown
		return errors.New("embedded etcd server took too long to start")
	}

	// Create client and run initialisation code
	logger.Debug("Creating client")
	client, err := clientv3.New(clientv3.Config{
		Endpoints: []string{clientURL.String()},
	})
	if err != nil {
		return err
	}

	return einit.InitEtcd(context.Background(), client, clusterName)
}
