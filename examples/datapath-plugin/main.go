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
	lxcInfo := req.GetAttachmentContext().GetLxc()
	if lxcInfo == nil {
		s.logger.Info("Skipping collection, since it's not for an LXC interface", "request", req)

		return nil, nil
	}

	s.logger.Info("Prepare pre/post hooks for programs", "pod", lxcInfo.GetPodInfo())

	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec
	for name := range req.GetCollection().GetPrograms() {
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

	return &datapathplugins.PrepareCollectionResponse{
		Hooks: hooks,
	}, nil
}

func (s *datapathPluginServer) InstrumentCollection(ctx context.Context, req *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	lxcInfo := req.GetAttachmentContext().GetLxc()
	if lxcInfo == nil {
		return nil, fmt.Errorf("collection is not for an LXC interface")
	}

	s.logger.Info("Add pre/post hooks for programs", "pod", lxcInfo.GetPodInfo())

	specByTarget := map[string]*ebpf.CollectionSpec{}
	for _, hook := range req.GetHooks() {
		if specByTarget[hook.Target] == nil {
			spec, err := loadLxc()
			if err != nil {
				return nil, fmt.Errorf("loading specs: %w", err)
			}
			specByTarget[hook.Target] = spec
		}

		spec := specByTarget[hook.Target]

		targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(hook.AttachTarget.ProgramId))
		if err != nil {
			return nil, fmt.Errorf("loading target program %d: %w", hook.AttachTarget.ProgramId, err)
		}
		defer targetProg.Close()

		var progSpec *ebpf.ProgramSpec
		if hook.Type == datapathplugins.HookType_PRE {
			progSpec = spec.Programs["before_lxc"]
		} else {
			progSpec = spec.Programs["after_lxc"]
		}
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = hook.AttachTarget.SubprogName
	}

	collByTarget := map[string]*lxcObjects{}
	for target, spec := range specByTarget {
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return nil, fmt.Errorf("loading collection for %s: %w", target, err)
		}
		defer coll.Close()
		var objs lxcObjects
		if err := coll.Assign(&objs); err != nil {
			return nil, fmt.Errorf("assigning collection for %s: %w", target, err)
		}
		defer objs.Close()
		collByTarget[target] = &objs

		if err := objs.lxcVariables.PodNamespace.Set(strToByte256(lxcInfo.GetPodInfo().GetNamespace())); err != nil {
			return nil, fmt.Errorf("setting pod namespace for %s: %w", target, err)
		}
		if err := objs.lxcVariables.PodName.Set(strToByte256(lxcInfo.GetPodInfo().GetPodName())); err != nil {
			return nil, fmt.Errorf("setting pod name for %s: %w", target, err)
		}
		if err := objs.lxcVariables.ProgramName.Set(strToByte256(target)); err != nil {
			return nil, fmt.Errorf("setting program name for %s: %w", target, err)
		}
	}

	for _, hook := range req.GetHooks() {
		coll := collByTarget[hook.Target]

		var prog *ebpf.Program
		if hook.Type == datapathplugins.HookType_PRE {
			prog = coll.BeforeLxc
		} else {
			prog = coll.AfterLxc
		}

		fmt.Printf("%v pin program to %s\n", hook.AttachTarget, hook.PinPath)
		if err := prog.Pin(hook.PinPath); err != nil {
			return nil, fmt.Errorf("pinning program to %s: %w", hook.PinPath, err)
		}
	}

	return &datapathplugins.InstrumentCollectionResponse{}, nil
}

func strToByte256(s string) [256]byte {
	var buf [256]byte

	copy(buf[:], s)

	return buf
}
