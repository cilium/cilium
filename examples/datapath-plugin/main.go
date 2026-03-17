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
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/ebpf"

	"google.golang.org/grpc"
)

func main() {
	bpffsPinPath := flag.String("bpffs-pin-path", "", "Parent directory for BPF program and map pins")
	unixSocketPath := flag.String("unix-socket-path", "", "UNIX socket to listen on")
	flag.Parse()

	logger := slog.Default()
	logger.Info("Starting plugin server",
		"listen-path", *unixSocketPath,
		"pin-path", *bpffsPinPath,
	)
	os.Remove(*unixSocketPath)
	err := runServer(logger, *unixSocketPath, *bpffsPinPath)
	logger.Error("Plugin server stopped",
		"error", err,
	)

	if err != nil {
		time.Sleep(2 * time.Minute)

		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, sockPath string, pinDir string) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	dps, err := newDatapathPluginServer(logger, pinDir)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	server := grpc.NewServer()
	datapathplugins.RegisterDatapathPluginServer(server, dps)

	return server.Serve(listener)
}

type datapathPluginServer struct {
	logger *slog.Logger
	pinDir string
}

func newDatapathPluginServer(logger *slog.Logger, pinDir string) (*datapathPluginServer, error) {
	s := &datapathPluginServer{
		logger: logger,
		pinDir: pinDir,
	}

	return s, nil
}

func (s *datapathPluginServer) PrepareCollection(ctx context.Context, req *datapathplugins.PrepareCollectionRequest) (*datapathplugins.PrepareCollectionResponse, error) {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	switch req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_, *datapathplugins.AttachmentContext_Lxc,
		*datapathplugins.AttachmentContext_Overlay_, *datapathplugins.AttachmentContext_Wireguard_:
		s.logger.Info("Prepare collection", "context", req.GetAttachmentContext())
		hooks = prepareSkbHooks(req.GetCollection().GetPrograms())
	default:
		s.logger.Info("Skip collection", "context", req.GetAttachmentContext())
		return nil, nil
	}

	return &datapathplugins.PrepareCollectionResponse{
		Hooks: hooks,
	}, nil
}

func (s *datapathPluginServer) InstrumentCollection(ctx context.Context, req *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	var acStr string

	switch ac := req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_:
		acStr = fmt.Sprintf("host/%s", ac.Host.GetIface().Name)
	case *datapathplugins.AttachmentContext_Lxc:
		acStr = fmt.Sprintf("lxc/%s/%s/%s",
			ac.Lxc.GetPodInfo().GetNamespace(),
			ac.Lxc.GetPodInfo().GetPodName(),
			ac.Lxc.GetIface().Name,
		)
	case *datapathplugins.AttachmentContext_Overlay_:
		acStr = fmt.Sprintf("overlay/%s", ac.Overlay.GetIface().Name)
	case *datapathplugins.AttachmentContext_Wireguard_:
		acStr = fmt.Sprintf("overlay/%s", ac.Wireguard.GetIface().Name)
	default:
		return nil, fmt.Errorf("unexpected attachment context: %v", req.AttachmentContext)
	}

	s.logger.Info("Instrument collection", "context", req.GetAttachmentContext())
	if err := loadAndPinSkb(acStr, req.GetHooks()); err != nil {
		return &datapathplugins.InstrumentCollectionResponse{}, err
	}

	return &datapathplugins.InstrumentCollectionResponse{}, nil
}

func strToByte256(s string) [256]byte {
	var buf [256]byte

	copy(buf[:], s)

	return buf
}

func prepareSkbHooks(programs map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec) []*datapathplugins.PrepareCollectionResponse_HookSpec {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	for name, prog := range programs {
		if !strings.HasSuffix(prog.SectionName, "/entry") {
			continue
		}
		if strings.HasPrefix(name, "cil_lxc_policy") {
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

func instrumentSkb(ctx *datapathplugins.AttachmentContext_LXC, hooks []*datapathplugins.InstrumentCollectionRequest_Hook) error {
	return loadAndPinSkb("", hooks)
}

func loadAndPinSkb(attachmentContext string, hooks []*datapathplugins.InstrumentCollectionRequest_Hook) error {
	specByTarget := map[string]*ebpf.CollectionSpec{}
	for _, hook := range hooks {
		if specByTarget[hook.Target] == nil {
			spec, err := loadSkb()
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
			progSpec = spec.Programs["before_skb"]
		} else {
			progSpec = spec.Programs["after_skb"]
		}
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = hook.AttachTarget.SubprogName
	}

	objsByTarget := map[string]*skbObjects{}

	for target, spec := range specByTarget {
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return fmt.Errorf("loading collection for %s: %w", target, err)
		}
		defer coll.Close()
		var objs skbObjects
		if err := coll.Assign(&objs); err != nil {
			return fmt.Errorf("assigning collection for %s: %w", target, err)
		}
		defer objs.Close()
		objsByTarget[target] = &objs
		if err := objs.skbVariables.AttachmentContext.Set(strToByte256(attachmentContext)); err != nil {
			return fmt.Errorf("setting attachment_context for %s: %w", target, err)
		}
	}

	for _, hook := range hooks {
		coll := objsByTarget[hook.Target]

		var prog *ebpf.Program
		if hook.Type == datapathplugins.HookType_PRE {
			prog = coll.BeforeSkb
		} else {
			prog = coll.AfterSkb
		}

		if err := prog.Pin(hook.PinPath); err != nil {
			return fmt.Errorf("pinning program to %s: %w", hook.PinPath, err)
		}
	}

	return nil
}
