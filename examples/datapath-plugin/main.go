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

	progs := req.GetCollection().GetPrograms()
	if progs != nil && progs["cil_from_container"] != nil {
		s.logger.Info("Attach pre/post hooks to cil_from_container", "pod", lxcInfo.GetPodInfo())
	} else {
		return nil, fmt.Errorf("no cil_from_container program in collection for lxc interface")
	}

	return &datapathplugins.PrepareCollectionResponse{
		Hooks: []*datapathplugins.PrepareCollectionResponse_HookSpec{
			{
				Type:   datapathplugins.HookType_PRE,
				Target: "cil_from_container",
			},
			{
				Type:   datapathplugins.HookType_POST,
				Target: "cil_from_container",
			},
		},
	}, nil
}

func (s *datapathPluginServer) InstrumentCollection(ctx context.Context, req *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	s.logger.Info("InstrumentCollection", "request", req)

	lxcInfo := req.GetAttachmentContext().GetLxc()
	if lxcInfo == nil {
		return nil, fmt.Errorf("collection is not for an LXC interface")
	}

	spec, err := loadPlugin()
	if err != nil {
		return nil, fmt.Errorf("loading specs: %w", err)
	}

	for _, h := range req.GetHooks() {
		targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(h.AttachTarget.ProgramId))
		if err != nil {
			return nil, fmt.Errorf("loading target program %d: %w", h.AttachTarget.ProgramId, err)
		}
		defer targetProg.Close()

		var progSpec *ebpf.ProgramSpec
		if h.Type == datapathplugins.HookType_PRE {
			progSpec = spec.Programs["before_cil_from_container"]
		} else {
			progSpec = spec.Programs["after_cil_from_container"]
		}
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = h.AttachTarget.SubprogName
	}

	var objs pluginObjects
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}
	defer coll.Close()
	if err := coll.Assign(&objs); err != nil {
		return nil, fmt.Errorf("assigning collection: %w", err)
	}
	defer objs.Close()

	if err := objs.pluginVariables.PodNamespace.Set(strToByte256(lxcInfo.GetPodInfo().GetNamespace())); err != nil {
		return nil, fmt.Errorf("setting pod namespace: %w", err)
	}
	if err := objs.pluginVariables.PodName.Set(strToByte256(lxcInfo.GetPodInfo().GetPodName())); err != nil {
		return nil, fmt.Errorf("setting pod name: %w", err)
	}

	for _, h := range req.GetHooks() {
		var prog *ebpf.Program
		if h.Type == datapathplugins.HookType_PRE {
			prog = objs.BeforeCilFromContainer
		} else {
			prog = objs.AfterCilFromContainer
		}
		if err := prog.Pin(h.PinPath); err != nil {
			return nil, fmt.Errorf("pinning program to %s: %w", h.PinPath, err)
		}
	}

	return &datapathplugins.InstrumentCollectionResponse{}, nil
}

func strToByte256(s string) [256]byte {
	var buf [256]byte

	copy(buf[:], s)

	return buf
}
