// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/datapath/plugins"
	cilebpf "github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	ciliumPreHookName   = "cil_pre"
	ciliumPostHookName  = "cil_post"
	ciliumReturnMapName = "cilium_return"
)

type DatapathPluginManager interface {
	IsEnabled() bool
	PrepareSpec(logger *slog.Logger, spec *ebpf.CollectionSpec) error
	ReplaceMaps() map[string]*ebpf.Map
	LoadSKBProgram(ctx context.Context, in *datapathplugins.LoadSKBProgramRequest) (*ebpf.Program, error)
}

var _ DatapathPluginManager = &datapathPluginManager{}

type datapathPluginManager struct {
	ciliumReturn *ebpf.Map
	pluginClient plugins.Client
}

func newDatapathPluginManager(logger *slog.Logger, pluginClient plugins.Client) (DatapathPluginManager, error) {
	var exitMapSpecs bpfgen.ExitsMapSpecs

	exitSpecs, err := bpfgen.LoadExits()
	if err != nil {
		return nil, fmt.Errorf("loading exit specs: %w", err)
	}
	if err := exitSpecs.Assign(&exitMapSpecs); err != nil {
		return nil, fmt.Errorf("assigning exit map specs: %w", err)
	}

	exitMapSpecs.CiliumReturn.Pinning = ebpf.PinByName
	ciliumReturn := cilebpf.NewMap(logger, exitMapSpecs.CiliumReturn)

	if pluginClient == nil {
		logger.Info("Plugins are disabled; remove map pin if present", logfields.Name, ciliumReturnMapName)
		if err := ciliumReturn.Unpin(); err != nil {
			logger.Warn("Removing map pin failed", logfields.Name, ciliumReturnMapName, logfields.Error, err)
		}
		return nil, nil
	}

	logger.Info("Plugins are enabled; ensure returns map exists", logfields.Name, ciliumReturnMapName)
	if err := ciliumReturn.OpenOrCreate(); err != nil {
		return nil, err
	}

	return &datapathPluginManager{
		ciliumReturn: ciliumReturn.Map,
		pluginClient: pluginClient,
	}, nil
}

func (m *datapathPluginManager) PrepareSpec(logger *slog.Logger, spec *ebpf.CollectionSpec) error {
	exitHandler, err := findExitHandler(spec)
	if err != nil {
		logger.Error("Could not instrument exit points", logfields.Error, err)
		return fmt.Errorf("finding exit program: %w", err)
	}

	if exitHandler == nil {
		logger.Debug("Nothing to do while instrumenting exit points; no exit handler was found")
		return nil
	}

	// We don't want to actually load this program.
	delete(spec.Programs, exitHandler.Name)

	if m.pluginClient == nil {
		logger.Debug("Don't instrument exit points; datapath plugins are disabled")
		return nil
	}

	logger.Debug("Instrumenting exit points", logfields.ProgName, exitHandler.Name)

	for _, prog := range spec.Programs {
		for i := 0; i < len(prog.Instructions); i++ {
			insn := prog.Instructions[i]

			if insn.OpCode.JumpOp() == asm.Exit {
				if i == len(prog.Instructions)-1 {
					logger.Debug("Drop exit instruction", logfields.ProgName, prog.Name, logfields.Instruction, i)
					prog.Instructions = prog.Instructions[:i]
				} else {
					logger.Debug("Convert exit instruction to jump", logfields.ProgName, prog.Name, logfields.Instruction, i)
					prog.Instructions[i] = asm.Ja.Imm(0, 0, fmt.Sprintf("exit_prelude_%s", prog.Name))
				}
			}
		}

		prog.Instructions = append(prog.Instructions, asm.Mov.Reg(asm.R1, asm.R0).WithSymbol(fmt.Sprintf("exit_prelude_%s", prog.Name)))
		for i := range exitHandler.Instructions {
			prog.Instructions = append(prog.Instructions, btf.WithFuncMetadata(exitHandler.Instructions[i].WithSymbol(""), nil))
		}
	}

	return nil
}

func findExitHandler(spec *ebpf.CollectionSpec) (*ebpf.ProgramSpec, error) {
	var exitHandler *ebpf.ProgramSpec

	for _, p := range spec.Programs {
		if strings.HasSuffix(p.SectionName, "/exit") {
			if exitHandler != nil {
				return nil, fmt.Errorf("only one exit handler is allowed")
			}

			exitHandler = p
		}
	}

	return exitHandler, nil
}

func (m *datapathPluginManager) IsEnabled() bool {
	return m.pluginClient != nil
}

func (m *datapathPluginManager) ReplaceMaps() map[string]*ebpf.Map {
	if m.ciliumReturn == nil {
		return nil
	}

	return map[string]*ebpf.Map{
		ciliumReturnMapName: m.ciliumReturn,
	}
}

func (m *datapathPluginManager) LoadSKBProgram(ctx context.Context, in *datapathplugins.LoadSKBProgramRequest) (*ebpf.Program, error) {
	if m.pluginClient == nil {
		return nil, fmt.Errorf("datapath plugins not enabled")
	}

	if in.Maps == nil {
		in.Maps = &datapathplugins.Maps{}
	}

	if err := m.injectMapIDs(in.Maps); err != nil {
		return nil, fmt.Errorf("injecting map ids: %w", err)
	}

	resp, err := m.pluginClient.LoadSKBProgram(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("rpc: %w", err)
	}

	if resp.ProgramPinPath == "" {
		return nil, nil
	}

	prog, err := ebpf.LoadPinnedProgram(resp.ProgramPinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("loading program from %s: %w", resp.ProgramPinPath, err)
	}

	if err := prog.Unpin(); err != nil {
		prog.Close()
		return nil, fmt.Errorf("unpinning program from %s: %w", resp.ProgramPinPath, err)
	}

	return prog, nil
}

func (m *datapathPluginManager) injectMapIDs(maps *datapathplugins.Maps) error {
	ciliumReturnID, err := mapID(m.ciliumReturn)
	if err != nil {
		return fmt.Errorf("cilium_return: %w", err)
	}

	maps.CiliumReturnMapId = uint32(ciliumReturnID)

	return nil

}

func mapID(m *ebpf.Map) (ebpf.MapID, error) {
	mi, err := m.Info()
	if err != nil {
		return 0, fmt.Errorf("getting map info: %w", err)
	}
	id, ok := mi.ID()
	if !ok {
		return 0, fmt.Errorf("could not get map id")
	}

	return id, nil
}
