// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/lumberjack/v2"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_bootstrap "github.com/cilium/proxy/go/envoy/config/bootstrap/v3"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_extensions_bootstrap_internal_listener_v3 "github.com/cilium/proxy/go/envoy/extensions/bootstrap/internal_listener/v3"
	envoy_config_upstream "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "envoy-manager")

var (
	// envoyLevelMap maps logrus.Level values to Envoy (spdlog) log levels.
	envoyLevelMap = map[logrus.Level]string{
		logrus.PanicLevel: "off",
		logrus.FatalLevel: "critical",
		logrus.ErrorLevel: "error",
		logrus.WarnLevel:  "warning",
		logrus.InfoLevel:  "info",
		logrus.DebugLevel: "debug",
		// spdlog "trace" not mapped
	}

	tracing = false
)

const (
	ciliumEnvoyStarter = "cilium-envoy-starter"
	ciliumEnvoy        = "cilium-envoy"
)

// EnableTracing changes Envoy log level to "trace", producing the most logs.
func EnableTracing() {
	tracing = true
}

func mapLogLevel(level logrus.Level) string {
	// Set Envoy loglevel to trace if debug AND verbose Engoy logging is enabled
	if level == logrus.DebugLevel && tracing {
		return "trace"
	}

	// Suppress the debug level if not debugging at flow level.
	if level == logrus.DebugLevel && !flowdebug.Enabled() {
		level = logrus.InfoLevel
	}

	return envoyLevelMap[level]
}

// Envoy manages a running Envoy proxy instance via the
// ListenerDiscoveryService and RouteDiscoveryService gRPC APIs.
type EmbeddedEnvoy struct {
	stopCh chan struct{}
	errCh  chan error
	admin  *EnvoyAdminClient
}

type embeddedEnvoyConfig struct {
	runDir                   string
	logPath                  string
	baseID                   uint64
	keepCapNetBindService    bool
	connectTimeout           int64
	maxRequestsPerConnection uint32
	maxConnectionDuration    time.Duration
	idleTimeout              time.Duration
}

// startEmbeddedEnvoy starts an Envoy proxy instance.
func startEmbeddedEnvoy(config embeddedEnvoyConfig) (*EmbeddedEnvoy, error) {
	envoy := &EmbeddedEnvoy{
		stopCh: make(chan struct{}),
		errCh:  make(chan error, 1),
		admin:  NewEnvoyAdminClientForSocket(GetSocketDir(config.runDir)),
	}

	bootstrapFilePath := filepath.Join(config.runDir, "envoy", "bootstrap.pb")

	writeBootstrapConfigFile(bootstrapConfig{
		filePath:                 bootstrapFilePath,
		nodeId:                   "host~127.0.0.1~no-id~localdomain", // node id format inherited from Istio
		cluster:                  ingressClusterName,
		adminPath:                getAdminSocketPath(GetSocketDir(config.runDir)),
		xdsSock:                  getXDSSocketPath(GetSocketDir(config.runDir)),
		egressClusterName:        egressClusterName,
		ingressClusterName:       ingressClusterName,
		connectTimeout:           config.connectTimeout,
		maxRequestsPerConnection: config.maxRequestsPerConnection,
		maxConnectionDuration:    config.maxConnectionDuration,
		idleTimeout:              config.idleTimeout,
	})

	log.Debugf("Envoy: Starting: %v", *envoy)

	// make it a buffered channel, so we can not only
	// read the written value but also skip it in
	// case no one reader reads it.
	started := make(chan bool, 1)
	go func() {
		var logWriter io.WriteCloser
		var logFormat string
		if config.logPath != "" {
			// Use the Envoy default log format when logging to a separate file
			logFormat = "[%Y-%m-%d %T.%e][%t][%l][%n] %v"
			logger := &lumberjack.Logger{
				Filename:   config.logPath,
				MaxSize:    100, // megabytes
				MaxBackups: 3,
				MaxAge:     28,   // days
				Compress:   true, // disabled by default
			}
			logWriter = logger
		} else {
			// Use log format that looks like Cilium logs when integrating logs
			// The logs will be reported as coming from the cilium-agent, so
			// we add the thread id to be able to differentiate between Envoy's
			// main and worker threads.
			logFormat = "%t|%l|%n|%v"

			// Create a piper that parses and writes into logrus the log
			// messages from Envoy.
			logWriter = newEnvoyLogPiper()
		}
		defer logWriter.Close()

		envoyArgs := []string{"-l", mapLogLevel(logging.GetLevel(logging.DefaultLogger)), "-c", bootstrapFilePath, "--base-id", strconv.FormatUint(config.baseID, 10), "--log-format", logFormat}
		envoyStarterArgs := []string{}
		if config.keepCapNetBindService {
			envoyStarterArgs = append(envoyStarterArgs, "--keep-cap-net-bind-service", "--")
		}
		envoyStarterArgs = append(envoyStarterArgs, envoyArgs...)

		for {
			cmd := exec.Command(ciliumEnvoyStarter, envoyStarterArgs...)
			cmd.Stderr = logWriter
			cmd.Stdout = logWriter

			if err := cmd.Start(); err != nil {
				log.WithError(err).Warn("Envoy: Failed to start proxy")
				select {
				case started <- false:
				default:
				}
				return
			}
			log.Debugf("Envoy: Started proxy")
			select {
			case started <- true:
			default:
			}

			log.Infof("Envoy: Proxy started with pid %d", cmd.Process.Pid)
			metrics.SubprocessStart.WithLabelValues(ciliumEnvoyStarter).Inc()

			// We do not return after a successful start, but watch the Envoy process
			// and restart it if it crashes.
			// Waiting for the process execution is done in the goroutime.
			// The purpose of the "crash channel" is to inform the loop about their
			// Envoy process crash - after closing that channel by the goroutime,
			// the loop continues, the channel is recreated and the new process
			// is watched again.
			crashCh := make(chan struct{})
			go func() {
				if err := cmd.Wait(); err != nil {
					log.WithError(err).Warn("Envoy: Proxy crashed")
					// Avoid busy loop & hogging CPU resources by waiting before restarting envoy.
					time.Sleep(100 * time.Millisecond)
				}
				close(crashCh)
			}()

			select {
			case <-crashCh:
				// Start Envoy again
				continue
			case <-envoy.stopCh:
				log.Infof("Envoy: Stopping proxy with pid %d", cmd.Process.Pid)
				if err := envoy.admin.quit(); err != nil {
					log.WithError(err).Fatalf("Envoy: Envoy admin quit failed, killing process with pid %d", cmd.Process.Pid)

					if err := cmd.Process.Kill(); err != nil {
						log.WithError(err).Fatal("Envoy: Stopping Envoy failed")
						envoy.errCh <- err
					}
				}
				close(envoy.errCh)
				return
			}
		}
	}()

	if <-started {
		return envoy, nil
	}

	return nil, errors.New("failed to start embedded Envoy server")
}

// newEnvoyLogPiper creates a writer that parses and logs log messages written by Envoy.
func newEnvoyLogPiper() io.WriteCloser {
	reader, writer := io.Pipe()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(nil, 1024*1024)
	go func() {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.LogSubsys: "unknown",
			logfields.ThreadID:  "unknown",
		})
		level := "debug"

		for scanner.Scan() {
			line := scanner.Text()
			var msg string

			parts := strings.SplitN(line, "|", 4)
			// Parse the line as a log message written by Envoy, assuming it
			// uses the configured format: "%t|%l|%n|%v".
			if len(parts) == 4 {
				threadID := parts[0]
				level = parts[1]
				loggerName := parts[2]
				// TODO: Parse msg to extract the source filename, line number, etc.
				msg = fmt.Sprintf("[%s", parts[3])

				scopedLog = log.WithFields(logrus.Fields{
					logfields.LogSubsys: fmt.Sprintf("envoy-%s", loggerName),
					logfields.ThreadID:  threadID,
				})
			} else {
				// If this line can't be parsed, it continues a multi-line log
				// message. In this case, log it at the same level and with the
				// same fields as the previous line.
				msg = line
			}

			if len(msg) == 0 {
				continue
			}

			// Map the Envoy log level to a logrus level.
			switch level {
			case "off", "critical", "error":
				scopedLog.Error(msg)
			case "warning":
				scopedLog.Warn(msg)
			case "info":
				scopedLog.Info(msg)
			case "debug", "trace":
				scopedLog.Debug(msg)
			default:
				scopedLog.Debug(msg)
			}
		}
		if err := scanner.Err(); err != nil {
			log.WithError(err).Error("Error while parsing Envoy logs")
		}
		reader.Close()
	}()
	return writer
}

// Stop kills the Envoy process started with startEmbeddedEnvoy. The gRPC API streams are terminated
// first.
func (e *EmbeddedEnvoy) Stop() error {
	close(e.stopCh)
	err, ok := <-e.errCh
	if ok {
		return err
	}
	return nil
}

func (e *EmbeddedEnvoy) GetAdminClient() *EnvoyAdminClient {
	return e.admin
}

type bootstrapConfig struct {
	filePath                 string
	nodeId                   string
	cluster                  string
	adminPath                string
	xdsSock                  string
	egressClusterName        string
	ingressClusterName       string
	connectTimeout           int64
	maxRequestsPerConnection uint32
	maxConnectionDuration    time.Duration
	idleTimeout              time.Duration
}

func writeBootstrapConfigFile(config bootstrapConfig) {
	useDownstreamProtocol := map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
			CommonHttpProtocolOptions: &envoy_config_core.HttpProtocolOptions{
				IdleTimeout:              durationpb.New(config.idleTimeout),
				MaxRequestsPerConnection: wrapperspb.UInt32(config.maxRequestsPerConnection),
				MaxConnectionDuration:    durationpb.New(config.maxConnectionDuration),
			},
			UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamProtocolConfig{
				UseDownstreamProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamHttpConfig{},
			},
		}),
	}

	useDownstreamProtocolAutoSNI := map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
			UpstreamHttpProtocolOptions: &envoy_config_core.UpstreamHttpProtocolOptions{
				//	Setting AutoSni or AutoSanValidation options here may crash
				//	Envoy, when Cilium Network filter already passes these from
				//	downstream to upstream.
			},
			CommonHttpProtocolOptions: &envoy_config_core.HttpProtocolOptions{
				IdleTimeout:              durationpb.New(config.idleTimeout),
				MaxRequestsPerConnection: wrapperspb.UInt32(config.maxRequestsPerConnection),
				MaxConnectionDuration:    durationpb.New(config.maxConnectionDuration),
			},
			UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamProtocolConfig{
				UseDownstreamProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamHttpConfig{},
			},
		}),
	}

	http2ProtocolOptions := map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_config_upstream.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
				},
			},
		}),
	}

	bs := &envoy_config_bootstrap.Bootstrap{
		Node: &envoy_config_core.Node{Id: config.nodeId, Cluster: config.cluster},
		StaticResources: &envoy_config_bootstrap.Bootstrap_StaticResources{
			Clusters: []*envoy_config_cluster.Cluster{
				{
					Name:                          egressClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 0},
					CleanupInterval:               &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocol,
				},
				{
					Name:                          egressTLSClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 0},
					CleanupInterval:               &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocolAutoSNI,
					TransportSocket: &envoy_config_core.TransportSocket{
						Name: "cilium.tls_wrapper",
						ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
							TypedConfig: toAny(&cilium.UpstreamTlsWrapperContext{}),
						},
					},
				},
				{
					Name:                          ingressClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 0},
					CleanupInterval:               &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocol,
				},
				{
					Name:                          ingressTLSClusterName,
					ClusterDiscoveryType:          &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
					ConnectTimeout:                &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 0},
					CleanupInterval:               &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 500000000},
					LbPolicy:                      envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
					TypedExtensionProtocolOptions: useDownstreamProtocolAutoSNI,
					TransportSocket: &envoy_config_core.TransportSocket{
						Name: "cilium.tls_wrapper",
						ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
							TypedConfig: toAny(&cilium.UpstreamTlsWrapperContext{}),
						},
					},
				},
				{
					Name:                 CiliumXDSClusterName,
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_STATIC},
					ConnectTimeout:       &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 0},
					LbPolicy:             envoy_config_cluster.Cluster_ROUND_ROBIN,
					LoadAssignment: &envoy_config_endpoint.ClusterLoadAssignment{
						ClusterName: CiliumXDSClusterName,
						Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
							LbEndpoints: []*envoy_config_endpoint.LbEndpoint{{
								HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
									Endpoint: &envoy_config_endpoint.Endpoint{
										Address: &envoy_config_core.Address{
											Address: &envoy_config_core.Address_Pipe{
												Pipe: &envoy_config_core.Pipe{Path: config.xdsSock},
											},
										},
									},
								},
							}},
						}},
					},
					TypedExtensionProtocolOptions: http2ProtocolOptions,
				},
				{
					Name:                 adminClusterName,
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_STATIC},
					ConnectTimeout:       &durationpb.Duration{Seconds: config.connectTimeout, Nanos: 0},
					LbPolicy:             envoy_config_cluster.Cluster_ROUND_ROBIN,
					LoadAssignment: &envoy_config_endpoint.ClusterLoadAssignment{
						ClusterName: adminClusterName,
						Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
							LbEndpoints: []*envoy_config_endpoint.LbEndpoint{{
								HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
									Endpoint: &envoy_config_endpoint.Endpoint{
										Address: &envoy_config_core.Address{
											Address: &envoy_config_core.Address_Pipe{
												Pipe: &envoy_config_core.Pipe{Path: config.adminPath},
											},
										},
									},
								},
							}},
						}},
					},
				},
			},
		},
		DynamicResources: &envoy_config_bootstrap.Bootstrap_DynamicResources{
			LdsConfig: CiliumXDSConfigSource,
			CdsConfig: CiliumXDSConfigSource,
		},
		Admin: &envoy_config_bootstrap.Admin{
			Address: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_Pipe{
					Pipe: &envoy_config_core.Pipe{Path: config.adminPath},
				},
			},
		},
		BootstrapExtensions: []*envoy_config_core.TypedExtensionConfig{
			{
				Name:        "envoy.bootstrap.internal_listener",
				TypedConfig: toAny(&envoy_extensions_bootstrap_internal_listener_v3.InternalListener{}),
			},
		},
		LayeredRuntime: &envoy_config_bootstrap.LayeredRuntime{
			Layers: []*envoy_config_bootstrap.RuntimeLayer{
				{
					Name: "static_layer_0",
					LayerSpecifier: &envoy_config_bootstrap.RuntimeLayer_StaticLayer{
						StaticLayer: &structpb.Struct{Fields: map[string]*structpb.Value{
							"overload": {Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"global_downstream_max_connections": {Kind: &structpb.Value_NumberValue{NumberValue: 50000}},
							}}}},
						}},
					},
				},
			},
		},
	}

	log.Debugf("Envoy: Bootstrap: %s", bs)
	data, err := proto.Marshal(bs)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error marshaling Envoy bootstrap")
	}
	err = os.WriteFile(config.filePath, data, 0644)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error writing Envoy bootstrap file")
	}
}

// getEmbeddedEnvoyVersion returns the envoy binary version string
func getEmbeddedEnvoyVersion() (string, error) {
	out, err := exec.Command(ciliumEnvoy, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute '%s --version': %w", ciliumEnvoy, err)
	}
	envoyVersionString := strings.TrimSpace(string(out))

	envoyVersionArray := strings.Fields(envoyVersionString)
	if len(envoyVersionArray) < 3 {
		return "", fmt.Errorf("failed to extract version from truncated Envoy version string")
	}

	return envoyVersionArray[2], nil
}
