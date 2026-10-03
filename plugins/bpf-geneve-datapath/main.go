// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/cilium/cilium/api/v1/datapathplugins"
)

const (
	PluginName               = "bpf-geneve-datapath"
	ciliumVersionMetadataKey = "cilium_version"

	logKeyCiliumVersion = ciliumVersionMetadataKey
	logKeyListenPath    = "listenPath"
	logKeyTraceID       = "traceId"
	logKeyRequest       = "request"
	logKeyResponse      = "response"
	logKeyError         = "error"
)

func main() {
	unixSocketPath := flag.String("unix-socket-path", "/var/run/cilium/plugins/bpf-geneve-datapath.sock", "UNIX socket to listen on")
	bpfObjPath := flag.String("bpf-obj-path", "", "Optional path to compiled geneve_plugin.o ELF for freplace attachment")
	flag.Parse()

	logger := slog.Default()
	logger.Info("Starting BPF Geneve datapath plugin server", logKeyListenPath, *unixSocketPath)

	os.Remove(*unixSocketPath)
	if err := runServer(logger, *unixSocketPath, *bpfObjPath); err != nil {
		logger.Error("BPF Geneve datapath plugin server failed", logKeyError, err)
		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, sockPath, bpfObjPath string) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return fmt.Errorf("resolving unix address: %w", err)
	}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("listening on unix socket: %w", err)
	}
	defer listener.Close()

	dps := newDatapathPluginServer(logger)
	dps.bpfObjPath = bpfObjPath
	server := grpc.NewServer()
	datapathplugins.RegisterDatapathPluginServer(server, dps)

	return server.Serve(listener)
}

type datapathPluginServer struct {
	logger     *slog.Logger
	bpfObjPath string
}

func newDatapathPluginServer(logger *slog.Logger) *datapathPluginServer {
	return &datapathPluginServer{
		logger: logger,
	}
}

func chooseHookProgram(hook *datapathplugins.InstrumentCollectionRequest_Hook) (string, error) {
	if hook == nil {
		return "", fmt.Errorf("hook is nil")
	}
	switch hook.Target {
	case "cil_from_netdev":
		if hook.Type == datapathplugins.HookType_PRE {
			return "geneve_from_netdev_pre", nil
		}
	case "cil_to_netdev":
		if hook.Type == datapathplugins.HookType_POST {
			return "geneve_to_netdev_post", nil
		}
	case "cil_from_container":
		if hook.Type == datapathplugins.HookType_PRE {
			return "geneve_from_container_pre", nil
		}
	case "cil_to_container":
		if hook.Type == datapathplugins.HookType_POST {
			return "geneve_to_container_post", nil
		}
	case "cil_from_overlay":
		if hook.Type == datapathplugins.HookType_PRE {
			return "geneve_from_overlay_pre", nil
		}
	case "cil_to_overlay":
		if hook.Type == datapathplugins.HookType_POST {
			return "geneve_to_overlay_post", nil
		}
	}
	return "", fmt.Errorf("unsupported hook target %q with type %s", hook.Target, hook.Type.String())
}

// PrepareCollection inspects the incoming attachment context and collection programs,
// and returns hook specifications to instrument native BPF Geneve datapath points.
func (s *datapathPluginServer) PrepareCollection(ctx context.Context, req *datapathplugins.PrepareCollectionRequest) (*datapathplugins.PrepareCollectionResponse, error) {
	if req.GetAttachmentContext() == nil {
		return nil, fmt.Errorf("attachment context is nil")
	}

	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	switch req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_:
		// In host context (physical netdevs like eth0):
		// - PRE on cil_from_netdev: intercepts incoming Geneve outer frames on UDP tunnel port
		// - POST on cil_to_netdev: inspects and validates encapsulated egress frames
		for progName := range req.GetCollection().GetPrograms() {
			switch progName {
			case "cil_from_netdev":
				hooks = append(hooks, &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:   datapathplugins.HookType_PRE,
					Target: progName,
				})
			case "cil_to_netdev":
				hooks = append(hooks, &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:   datapathplugins.HookType_POST,
					Target: progName,
				})
			}
		}

	case *datapathplugins.AttachmentContext_Lxc:
		// In container context:
		// - PRE on cil_from_container: inspects egress pod traffic for tunnel routing
		// - POST on cil_to_container: monitors delivered packets after decapsulation
		for progName := range req.GetCollection().GetPrograms() {
			switch progName {
			case "cil_from_container":
				hooks = append(hooks, &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:   datapathplugins.HookType_PRE,
					Target: progName,
				})
			case "cil_to_container":
				hooks = append(hooks, &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:   datapathplugins.HookType_POST,
					Target: progName,
				})
			}
		}

	case *datapathplugins.AttachmentContext_Overlay_:
		// In overlay context:
		for progName := range req.GetCollection().GetPrograms() {
			switch progName {
			case "cil_from_overlay":
				hooks = append(hooks, &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:   datapathplugins.HookType_PRE,
					Target: progName,
				})
			case "cil_to_overlay":
				hooks = append(hooks, &datapathplugins.PrepareCollectionResponse_HookSpec{
					Type:   datapathplugins.HookType_POST,
					Target: progName,
				})
			}
		}

	default:
		// Other contexts (e.g. socket) do not require Geneve L3/L4 encap/decap hooks
		return &datapathplugins.PrepareCollectionResponse{}, nil
	}

	cookie := uuid.New().String()
	resp := &datapathplugins.PrepareCollectionResponse{
		Hooks:  hooks,
		Cookie: cookie,
	}

	s.logger.Info("PrepareCollection completed",
		logKeyCiliumVersion, ciliumVersion(ctx),
		logKeyTraceID, cookie,
		"context", attachmentContextSummary(req.GetAttachmentContext()),
		"hookCount", len(hooks),
	)

	return resp, nil
}

// InstrumentCollection validates and instruments the requested freplace hooks.
func (s *datapathPluginServer) InstrumentCollection(ctx context.Context, req *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	logger := s.logger.With(logKeyTraceID, req.GetCookie())

	usedHookPrograms := make(map[string]bool, len(req.GetHooks()))
	hasLiveTargets := s.bpfObjPath != ""

	for _, hook := range req.GetHooks() {
		progName, err := chooseHookProgram(hook)
		if err != nil {
			return nil, err
		}
		usedHookPrograms[progName] = true
		if hook.GetAttachTarget() == nil || hook.GetAttachTarget().GetProgramId() == 0 {
			hasLiveTargets = false
		}

		logger.Debug("Instrumenting hook",
			"target", hook.Target,
			"hookProgram", progName,
			"type", hook.Type.String(),
			"pinPath", hook.PinPath,
		)
	}

	if hasLiveTargets && len(req.GetHooks()) > 0 {
		spec, err := ebpf.LoadCollectionSpec(s.bpfObjPath)
		if err != nil {
			return nil, fmt.Errorf("loading plugin BPF collection spec %s: %w", s.bpfObjPath, err)
		}

		targetProgs := make(map[ebpf.ProgramID]*ebpf.Program)
		for _, hook := range req.GetHooks() {
			progName, _ := chooseHookProgram(hook)
			progSpec := spec.Programs[progName]
			if progSpec == nil {
				return nil, fmt.Errorf("BPF hook program %q not found in %s", progName, s.bpfObjPath)
			}

			id := ebpf.ProgramID(hook.GetAttachTarget().GetProgramId())
			if targetProgs[id] == nil {
				targetProg, err := ebpf.NewProgramFromID(id)
				if err != nil {
					return nil, fmt.Errorf("opening target program %d: %w", id, err)
				}
				defer targetProg.Close()
				targetProgs[id] = targetProg
			}

			progSpec.AttachTarget = targetProgs[id]
			progSpec.AttachTo = hook.GetAttachTarget().GetSubprogName()
		}

		for name := range spec.Programs {
			if !usedHookPrograms[name] {
				delete(spec.Programs, name)
			}
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return nil, fmt.Errorf("loading plugin BPF collection: %w", err)
		}
		defer coll.Close()

		for _, hook := range req.GetHooks() {
			progName, _ := chooseHookProgram(hook)
			prog := coll.Programs[progName]
			if err := prog.Pin(hook.PinPath); err != nil {
				return nil, fmt.Errorf("pinning hook program %s to %s: %w", progName, hook.PinPath, err)
			}
		}
	}

	logger.Info("InstrumentCollection completed",
		logKeyCiliumVersion, ciliumVersion(ctx),
		"hookCount", len(req.GetHooks()),
	)

	return &datapathplugins.InstrumentCollectionResponse{}, nil
}

func ciliumVersion(ctx context.Context) string {
	version := "unknown"
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		versionMd := md.Get(ciliumVersionMetadataKey)
		if len(versionMd) == 1 {
			version = versionMd[0]
		}
	}
	return version
}

func attachmentContextSummary(ac *datapathplugins.AttachmentContext) string {
	if ac == nil {
		return "nil"
	}
	switch c := ac.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_:
		return path.Join("host", c.Host.GetIface().Name)
	case *datapathplugins.AttachmentContext_Lxc:
		return path.Join("lxc", c.Lxc.GetPodInfo().GetName())
	case *datapathplugins.AttachmentContext_Overlay_:
		return path.Join("overlay", c.Overlay.GetIface().Name)
	default:
		return "other"
	}
}
