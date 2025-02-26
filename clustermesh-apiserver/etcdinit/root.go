// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package etcdinit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/cilium/cilium/pkg/defaults"
	kvstoreEtcdInit "github.com/cilium/cilium/pkg/kvstore/etcdinit"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

// EtcdBinaryLocation is hardcoded because we expect this command to be run inside a Cilium container that places the
// etcd binary in a specific location.
const EtcdBinaryLocation = "/usr/bin/etcd"

var (
	vp = viper.New()
)

func NewCmd() *cobra.Command {
	log := logging.DefaultLogger.With(slog.String(logfields.LogSubsys, "etcdinit"))
	rootCmd := &cobra.Command{
		Use:   "etcdinit",
		Short: "Initialize an etcd data directory for use by the etcd sidecar of clustermesh-apiserver",
		PreRun: func(cmd *cobra.Command, args []string) {
			option.LogRegisteredOptions(vp, log)
			log.Info("Cilium ClusterMesh etcd init", slog.String("version", version.Version))
		},
		Run: func(cmd *cobra.Command, args []string) {
			err := InitEtcdLocal(log)
			// The error has already been handled and logged by InitEtcdLocal. We just use it to determine the exit code
			if err != nil {
				os.Exit(-1)
			}
		},
	}
	rootCmd.Flags().String("etcd-data-dir", "/var/run/etcd", "Etcd data directory. Should have read/write permissions here.")
	rootCmd.Flags().String("etcd-initial-cluster-token", "clustermesh-apiserver", "Etcd initial cluster token. Used to prevent accidentally joining other etcd clusters that are reachable on the same L2 network domain.")
	rootCmd.Flags().String("etcd-cluster-name", "clustermesh-apiserver", "Name of the etcd cluster. Must match what etcd is later started with.")
	rootCmd.Flags().String("cluster-name", defaults.ClusterName, "Name of the Cilium cluster, used to set the username of the admin user in etcd. This is distinct from the etcd cluster's name.")
	rootCmd.Flags().Duration("timeout", time.Minute*2, "How long to wait for operations before exiting.")
	rootCmd.Flags().Bool("debug", false, "Debug log output.")
	// Use Viper for configuration so that we can parse both command line flags and environment variables
	vp.BindPFlags(rootCmd.Flags())
	vp.SetEnvPrefix("cilium")
	vp.AutomaticEnv()
	vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	return rootCmd
}

func InitEtcdLocal(log *slog.Logger) (returnErr error) {
	// Get configuration values
	etcdDataDir := vp.GetString("etcd-data-dir")
	etcdInitialClusterToken := vp.GetString("etcd-initial-cluster-token")
	etcdClusterName := vp.GetString("etcd-cluster-name")
	ciliumClusterName := vp.GetString("cluster-name")
	debug := vp.GetBool("debug")
	timeout := vp.GetDuration("timeout")
	// We have returnErr has a named variable, so we can set it in the deferred cleanup function if needed
	log.Info(
		"Starting first-time initialisation of etcd for Cilium Clustermesh",
		slog.Duration("timeout", timeout),
		slog.String("etcdDataDir", etcdDataDir),
		slog.String("etcdClusterName", etcdClusterName),
		slog.String(logfields.ClusterName, ciliumClusterName),
		slog.String("etcdInitialClusterToken", etcdInitialClusterToken),
	)

	ctx, cancelFn := context.WithTimeout(context.Background(), timeout)
	defer cancelFn()

	if debug {
		logging.SetLogLevelToDebug()
	}
	log.Debug("Debug logging enabled")

	// When the clustermesh-apiserver is launched we create a new etcd. We don't support persistence, so it is safe to
	// delete the contents of the data directory before we start. It should be empty as we use a Kubernetes emptyDir for
	// this purpose, but if the initialization failed Kubernetes may re-run this operation and emptyDir is tied to the
	// lifecycle of the whole pod. Therefore, it could contain files from a previously failed initialization attempt.
	log.Info(
		"Deleting contents of data directory",
		slog.String("etcdDataDir", etcdDataDir),
	)
	// We don't use os.RemoveAll on the etcdDataDirectory because we don't want to remove the directory itself, just
	// everything inside of it. In most cases that directory will be a mount anyway.
	dir, err := os.ReadDir(etcdDataDir)
	if err != nil {
		log.Info(
			"Failed to read from the etcd data directory while attempting to delete existing files",
			slog.Any(logfields.Error, err),
			slog.String("etcdDataDir", etcdDataDir),
		)
		return err
	}
	for _, d := range dir {
		log.Debug(
			"Removing file/directory in data dir",
			slog.String("etcdDataDir", etcdDataDir),
			slog.String("path", d.Name()),
		)
		err = os.RemoveAll(path.Join(etcdDataDir, d.Name()))
		if err != nil {
			log.Error(
				"Failed to remove pre-existing file/directory in etcd data directory",
				slog.Any(logfields.Error, err),
				slog.String("etcdDataDir", etcdDataDir),
				slog.String("path", d.Name()),
			)
			return err
		}
	}

	// Use "localhost" (instead of "http://127.0.0.1:2379" or "http://[::1]:2379") so it works in both the IPv4 and
	// IPv6 cases.
	loopbackEndpoint := "http://localhost:2379"
	log.Info(
		"Starting localhost-only etcd process",
		slog.String("etcdDataDir", etcdDataDir),
		slog.String("etcdListenClientUrl", loopbackEndpoint),
		slog.String("etcdClusterName", etcdClusterName),
		slog.String("etcdInitialClusterToken", etcdInitialClusterToken),
	)
	// Specify the full path to the etcd binary to avoid any PATH search binary replacement nonsense
	etcdCmd := exec.CommandContext(ctx, EtcdBinaryLocation,
		fmt.Sprintf("--data-dir=%s", etcdDataDir),
		fmt.Sprintf("--name=%s", etcdClusterName),
		fmt.Sprintf("--listen-client-urls=%s", loopbackEndpoint),
		fmt.Sprintf("--advertise-client-urls=%s", loopbackEndpoint),
		fmt.Sprintf("--initial-cluster-token=%s", etcdInitialClusterToken),
		"--initial-cluster-state=new")

	log.Debug(
		"Executing etcd",
		slog.String("etcdBinary", EtcdBinaryLocation),
		slog.Any("etcdFlags", etcdCmd.Args),
	)

	// Exec the etcd binary, which ultimately calls fork(2) under the hood. We don't wait on its completion, because
	// it'll never complete of course.
	err = etcdCmd.Start()
	if err != nil {
		log.Error(
			"Failed to launch etcd process",
			slog.Any(logfields.Error, err),
			slog.String("etcdBinary", EtcdBinaryLocation),
			slog.Any("etcdFlags", etcdCmd.Args),
		)
		return err
	}
	etcdPid := etcdCmd.Process.Pid
	log.Info(
		"Local etcd server process started",
		slog.Int("etcdPID", etcdPid),
	)

	// Defer etcd process cleanup
	defer func() {
		logAttr := slog.Int("etcdPID", etcdPid)
		log.Debug("Cleaning up etcd process", logAttr)
		// Send the process a SIGTERM. SIGTERM is the "gentle" shutdown signal, and etcd should close down its resources
		// cleanly and then exit.
		log.Info("Sending SIGTERM signal to etcd process", logAttr)
		err := etcdCmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			log.Error(
				"Failed to send SIGTERM signal to etcd process",
				slog.Any(logfields.Error, err),
				logAttr,
			)
			// Return both this error, and the main function's return error (if there is one).
			returnErr = errors.Join(returnErr, err)
			return
		}

		// Wait for the etcd process to finish, and cleanup resources.
		log.Info("Waiting for etcd process to exit")
		err = etcdCmd.Wait()
		if err != nil {
			exitError := &exec.ExitError{}
			if errors.As(err, &exitError) {
				if exitError.ExitCode() == -1 {
					// We SIGTERMed the etcd process, so a nonzero exit code is expected.
					// Check the context as a last sanity check
					if ctx.Err() != nil {
						// Don't log the error itself here, if the context is timed out it'll be cancelled, so the error
						// will just say "context cancelled" and not be useful — and possibly even misleading. It's
						// possible that the timeout expires at the moment between etcd exiting normally and this check,
						// which would report a false error. That's very unlikely, so we don't worry about it here.
						log.Error("etcd exited, but our context has expired. etcd may have been terminated due to timeout. Consider increasing the value of the timeout using the --timeout flag or CILIUM_TIMEOUT environment variable.",
							slog.Duration("timeout", timeout),
							logAttr,
						)
						// Return both this error, and the main function's return error (if there is one). This is just
						// to make sure that the calling code correctly detects that an error occurs.
						returnErr = errors.Join(returnErr, ctx.Err())
						return
					}
					// This is the "good state", the context hasn't expired, the etcd process has exited, and we're
					// okay with a nonzero exit code because we exited it with a SIGTERM.
					log.Info("etcd process exited", logAttr)
					return
				}
				log.Error(
					"etcd process exited improperly",
					slog.Any(logfields.Error, err),
					slog.Int("etcdExitCode", exitError.ExitCode()),
					logAttr,
				)
				// Return both this error, and the main function's return error (if there is one).
				returnErr = errors.Join(returnErr, err)
				return
			} else {
				// Some other kind of error
				log.Error(
					"Failed to wait on etcd process finishing",
					slog.Any(logfields.Error, err),
					logAttr,
				)
				// Return both this error, and the main function's return error (if there is one).
				returnErr = errors.Join(returnErr, err)
				return
			}
		}
		log.Info("etcd process exited", logAttr)
	}()

	// With the etcd server process launched, we need to construct an etcd client
	//exhaustruct:ignore // Not all etcd config options are required.
	config := clientv3.Config{
		Context:   ctx,
		Endpoints: []string{loopbackEndpoint},
	}
	log.Debug("Constructed etcd client config", slog.Any("etcdClientConfig", config))
	etcdClient, err := clientv3.New(config)
	if err != nil {
		log.Error(
			"Failed to construct etcd client from configuration",
			slog.Any(logfields.Error, err),
			slog.Any("etcdClientConfig", config),
		)
		return err
	}
	defer etcdClient.Close()

	// Run the init commands
	log.Info(
		"Starting etcd init",
		slog.String(logfields.ClusterName, ciliumClusterName),
	)
	err = kvstoreEtcdInit.ClusterMeshEtcdInit(ctx, log, etcdClient, ciliumClusterName)
	if err != nil {
		log.Error(
			"Failed to initialise etcd",
			slog.Any(logfields.Error, err),
			slog.Any(logfields.ClusterName, ciliumClusterName),
		)
		return err
	}
	log.Info("Etcd init completed")
	return nil
}
