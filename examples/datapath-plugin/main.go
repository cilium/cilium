// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/datapathplugins"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	ciliumVersionMetadataKey = "cilium_version"

	logKeyCiliumVersion = ciliumVersionMetadataKey
	logKeyListenPath    = "listenPath"
	logKeyRequest       = "request"
	logKeyResponse      = "response"
	logKeyTraceId       = "traceId"
	logKeyError         = "error"

	preHookName  = "before"
	postHookName = "after"
)

func main() {
	unixSocketPath := flag.String("unix-socket-path", "", "UNIX socket to listen on")
	flag.Parse()

	logger := slog.Default()
	logger.Info("Starting plugin server", logKeyListenPath, *unixSocketPath)
	os.Remove(*unixSocketPath)
	err := runServer(logger, *unixSocketPath)
	logger.Error("Plugin server stopped",
		logKeyError, err,
	)

	if err != nil {
		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, sockPath string) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
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

	return s, nil
}

func (s *datapathPluginServer) PrepareCollection(ctx context.Context, req *datapathplugins.PrepareCollectionRequest) (*datapathplugins.PrepareCollectionResponse, error) {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	switch req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_, *datapathplugins.AttachmentContext_Lxc,
		*datapathplugins.AttachmentContext_Overlay_, *datapathplugins.AttachmentContext_Wireguard_:
		hooks = prepareSKBAndXDPHooks(req.GetCollection().GetPrograms())
	case *datapathplugins.AttachmentContext_Xdp:
		hooks = prepareSKBAndXDPHooks(req.GetCollection().GetPrograms())
	case *datapathplugins.AttachmentContext_Socket_:
		hooks = prepareSockHooks(req.GetCollection().GetPrograms())
	default:
		s.logger.Info("PrepareCollection()",
			logKeyCiliumVersion, ciliumVersion(ctx),
			logKeyRequest, req,
			logKeyResponse, "nil",
		)

		return nil, nil
	}

	id := uuid.New().String()
	resp := &datapathplugins.PrepareCollectionResponse{
		Hooks:  hooks,
		Cookie: id,
	}

	s.logger.Info("PrepareCollection()",
		logKeyCiliumVersion, ciliumVersion(ctx),
		logKeyTraceId, id,
		logKeyRequest, req,
		logKeyResponse, resp,
	)

	return resp, nil
}

func (s *datapathPluginServer) InstrumentCollection(ctx context.Context, req *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	logger := s.logger.With(logKeyTraceId, req.GetCookie())

	if err := loadAndPin(req.GetAttachmentContext(), req.GetHooks(), req.GetPins()); err != nil {
		logger.Error("InstrumentCollection()",
			logKeyCiliumVersion, ciliumVersion(ctx),
			logKeyRequest, req,
			logKeyError, err,
		)

		return nil, err
	} else {
		logger.Info("InstrumentCollection()",
			logKeyCiliumVersion, ciliumVersion(ctx),
			logKeyRequest, req,
		)
	}

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

func strToByte256(s string) [256]byte {
	var buf [256]byte

	copy(buf[:], s)

	return buf
}

func prepareSKBAndXDPHooks(programs map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec) []*datapathplugins.PrepareCollectionResponse_HookSpec {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	for name, prog := range programs {
		if !strings.HasSuffix(prog.SectionName, "/entry") {
			continue
		}
		if name == "cil_lxc_policy" ||
			name == "cil_lxc_policy_egress" ||
			name == "cil_host_policy" {
			continue
		}

		hooks = append(hooks,
			&datapathplugins.PrepareCollectionResponse_HookSpec{
				Type:   datapathplugins.HookType_PRE,
				Target: name,
			},
			&datapathplugins.PrepareCollectionResponse_HookSpec{
				Type:   datapathplugins.HookType_POST,
				Target: name,
			},
		)
	}

	return hooks
}

func prepareSockHooks(programs map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec) []*datapathplugins.PrepareCollectionResponse_HookSpec {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	for name := range programs {
		hooks = append(hooks,
			&datapathplugins.PrepareCollectionResponse_HookSpec{
				Type:   datapathplugins.HookType_PRE,
				Target: name,
			},
			&datapathplugins.PrepareCollectionResponse_HookSpec{
				Type:   datapathplugins.HookType_POST,
				Target: name,
			},
		)
	}

	return hooks
}

func loadAndPin(ac *datapathplugins.AttachmentContext, hooks []*datapathplugins.InstrumentCollectionRequest_Hook, pinPath string) error {
	acStr, err := attachmentContextStr(ac)
	if err != nil {
		return err
	}

	specByTarget := map[string]*ebpf.CollectionSpec{}
	for _, hook := range hooks {
		if specByTarget[hook.Target] == nil {
			spec, err := collectionSpec(ac, hook.Target)
			if err != nil {
				return fmt.Errorf("loading specs: %w", err)
			}
			specByTarget[hook.Target] = spec
		}

		spec := specByTarget[hook.Target]

		targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(hook.AttachTarget.ProgramId))
		if err != nil {
			return fmt.Errorf("loading target program %d: %w", hook.AttachTarget.ProgramId, err)
		}
		defer targetProg.Close()

		var progSpec *ebpf.ProgramSpec
		if hook.Type == datapathplugins.HookType_PRE {
			progSpec = spec.Programs[preHookName]
		} else {
			progSpec = spec.Programs[postHookName]
		}
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = hook.AttachTarget.SubprogName
	}

	objsByTarget := map[string]*ebpf.Collection{}

	for target, spec := range specByTarget {
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
		})
		if err != nil {
			return fmt.Errorf("loading collection for %s: %w", target, err)
		}
		defer coll.Close()
		objsByTarget[target] = coll
		if err := coll.Variables["attachment_context"].Set(strToByte256(fmt.Sprintf("%s %s()", acStr, target))); err != nil {
			return fmt.Errorf("setting attachment_context for %s: %w", target, err)
		}
	}

	for _, hook := range hooks {
		coll := objsByTarget[hook.Target]

		var prog *ebpf.Program
		if hook.Type == datapathplugins.HookType_PRE {
			prog = coll.Programs[preHookName]
		} else {
			prog = coll.Programs[postHookName]
		}

		if err := prog.Pin(hook.PinPath); err != nil {
			return fmt.Errorf("pinning program to %s: %w", hook.PinPath, err)
		}
	}

	return nil
}

func attachmentContextStr(ac *datapathplugins.AttachmentContext) (string, error) {
	var acStr string

	switch ac := ac.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_:
		acStr = path.Join("host", ac.Host.GetIface().Name)
	case *datapathplugins.AttachmentContext_Lxc:
		acStr = path.Join(
			"lxc",
			ac.Lxc.GetPodInfo().GetNamespace(),
			ac.Lxc.GetPodInfo().GetName(),
			ac.Lxc.GetIface().Name,
		)
	case *datapathplugins.AttachmentContext_Overlay_:
		acStr = path.Join("overlay", ac.Overlay.GetIface().Name)
	case *datapathplugins.AttachmentContext_Wireguard_:
		acStr = path.Join("wireguard", ac.Wireguard.GetIface().Name)
	case *datapathplugins.AttachmentContext_Socket_:
		acStr = "socket"
	case *datapathplugins.AttachmentContext_Xdp:
		acStr = path.Join("xdp", ac.Xdp.GetIface().Name)
	default:
		return "", fmt.Errorf("unexpected attachment context: %v", ac)
	}

	return acStr, nil
}

func collectionSpec(attachmentContext *datapathplugins.AttachmentContext, target string) (*ebpf.CollectionSpec, error) {
	if attachmentContext.GetSocket() != nil {
		switch target {
		case "cil_sock4_connect", "cil_sock4_pre_bind",
			"cil_sock4_sendmsg", "cil_sock4_recvmsg",
			"cil_sock4_getpeername", "cil_sock6_connect",
			"cil_sock6_pre_bind", "cil_sock6_sendmsg",
			"cil_sock6_recvmsg", "cil_sock6_getpeername":
			return loadSock_addr()
		case "cil_sock4_post_bind", "cil_sock6_post_bind",
			"cil_sock_release":
			return loadSock()
		}

		return nil, fmt.Errorf("unrecognized socket program: %s", target)
	} else if attachmentContext.GetXdp() != nil {
		return loadXdp()
	}

	return loadSkb()
}
