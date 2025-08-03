// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/cilium/api/v1/datapathplugins"

	"github.com/cilium/ebpf"

	"google.golang.org/grpc"
)

var (
	bpffsPinPath        = flag.String("bpffs-pin-path", "", "Parent directory for BPF program and map pins")
	unixSocketPath      = flag.String("unix-socket-path", "", "UNIX socket to listen on")
	httpProxyListenPort = flag.Int("http-proxy-listen-port", 8080, "Listen port for the HTTP proxy server")
	clientPodName       = flag.String("client-pod-name", "", "Name of the pod whose traffic we want to proxy")
)

func main() {
	flag.Parse()

	logger := slog.Default()

	go func() {
		logger.Info("Starting http proxy server",
			"port", *httpProxyListenPort,
		)
		err := runTProxyServer(logger)
		logger.Error("Proxy server stopped", "error", err)

		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}()

	logger.Info("Starting plugin server",
		"listen-path", *unixSocketPath,
		"pin-path", *bpffsPinPath,
		"client-pod-name", *clientPodName,
	)
	err := runDatapathPluginServer(logger)
	logger.Error("Plugin server stopped", "error", err)

	if err != nil {
		os.Exit(1)
	}
}

func runTProxyServer(logger *slog.Logger) error {
	http.Handle("/", &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			logger.Info("In",
				"method", pr.In.Method,
				"host", pr.In.Host,
				"url", pr.In.URL.String(),
			)
			pr.Out.Header.Set("My-Special-Header", "1")
			pr.Out.URL = pr.In.URL
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			// pr.Out.URL, _ = url.Parse(pr.In.URL.String())
			// pr.Out.URL.Host = fmt.Sprint(pr.In.Context().Value(http.LocalAddrContextKey))
			logger.Info("Out",
				"method", pr.Out.Method,
				"host", pr.Out.Host,
				"url", pr.Out.URL.String(),
			)
		},
	})

	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			var sockOptErr error
			var fn = func(s uintptr) {
				logger.Info("Set sockopt")
				sockOptErr = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}
			if err := c.Control(fn); err != nil {
				return fmt.Errorf("calling control: %w", err)
			}
			if sockOptErr != nil {
				return fmt.Errorf("configuring socket: %w", sockOptErr)
			}

			return nil
		},
	}
	logger.Info("Start listener")
	listener, err := lc.Listen(context.Background(), "tcp4", fmt.Sprintf(":%d", *httpProxyListenPort))
	if err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	logger.Info("Start serving")
	return http.Serve(listener, nil)
}

func runDatapathPluginServer(logger *slog.Logger) error {
	os.Remove(*unixSocketPath)
	addr, err := net.ResolveUnixAddr("unix", *unixSocketPath)
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	dps, err := newDatapathPluginServer(logger)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	server := grpc.NewServer()
	datapathplugins.RegisterDatapathPluginServer(server, dps)

	return server.Serve(listener)
}

type datapathPluginServer struct {
	logger *slog.Logger
}

func newDatapathPluginServer(logger *slog.Logger) (*datapathPluginServer, error) {
	s := &datapathPluginServer{
		logger: logger,
	}

	if err := mkdirBPF(s.GlobalsPinDir()); err != nil {
		return nil, fmt.Errorf("ensuring pin dir %s: %w", s.GlobalsPinDir(), err)
	}

	if err := mkdirBPF(s.ProgramsPinDir()); err != nil {
		return nil, fmt.Errorf("ensuring pin dir %s: %w", s.ProgramsPinDir(), err)
	}

	return s, nil
}

func (s *datapathPluginServer) LoadSKBProgram(ctx context.Context, req *datapathplugins.LoadSKBProgramRequest) (*datapathplugins.LoadSKBProgramResponse, error) {
	s.logger.Info("LoadSKBProgram()", "request", req)

	var mapReplacements map[string]*ebpf.Map
	switch req.AttachmentPoint.Anchor {
	case datapathplugins.Anchor_BEFORE:
		// Nothing to do
	case datapathplugins.Anchor_AFTER:
		ciliumReturn, err := ebpf.NewMapFromID(ebpf.MapID(req.Maps.CiliumReturnMapId))
		if err != nil {
			return nil, fmt.Errorf("loading cilium_return map: %w", err)
		}
		defer ciliumReturn.Close()

		mapReplacements = map[string]*ebpf.Map{
			"cilium_return": ciliumReturn,
		}
	default:
		return nil, fmt.Errorf("invalid anchor: %w", req.AttachmentPoint.Anchor)
	}

	if req.DeviceType != datapathplugins.DeviceType_LXC ||
		req.AttachmentPoint.Anchor != datapathplugins.Anchor_AFTER ||
		req.AttachmentPoint.Direction != datapathplugins.Direction_INGRESS ||
		req.EndpointConfig.K8SPodName != *clientPodName {
		return &datapathplugins.LoadSKBProgramResponse{}, nil
	}

	pluginSpec, err := loadPlugin()
	if err != nil {
		return nil, fmt.Errorf("loading demo spec: %w", err)
	}

	var objs pluginObjects
	coll, err := ebpf.NewCollectionWithOptions(pluginSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: s.GlobalsPinDir(),
		},
		MapReplacements: mapReplacements,
	})
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Fprintf(os.Stderr, "Verifier error: %+v\n", ve)
	}
	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}
	defer coll.Close()

	if err := coll.Assign(&objs); err != nil {
		return nil, fmt.Errorf("assigning objects: %w", err)
	}

	if err := objs.pluginVariables.ProxyPort.Set(uint16(*httpProxyListenPort)); err != nil {
		return nil, fmt.Errorf("configuring proxy port: %w", err)
	}

	pinPath := s.ProgramPinPath(req.AttachmentPoint)
	if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("unpinning program from %s: %w", pinPath, err)
	}
	if err := objs.pluginPrograms.FromClient.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pinning program to %s: %w", pinPath, err)
	}

	return &datapathplugins.LoadSKBProgramResponse{
		ProgramPinPath: pinPath,
	}, nil
}

func (s *datapathPluginServer) GlobalsPinDir() string {
	return filepath.Join(*bpffsPinPath, "globals")
}

func (s *datapathPluginServer) ProgramsPinDir() string {
	return filepath.Join(*bpffsPinPath, "programs")
}

func (s *datapathPluginServer) ProgramPinPath(ap *datapathplugins.AttachmentPoint) string {
	return filepath.Join(s.ProgramsPinDir(), fmt.Sprintf("%s-%s-%s", ap.DeviceName, ap.Direction.String(), ap.Anchor.String()))
}

func mkdirBPF(path string) error {
	return os.MkdirAll(path, 0755)
}
