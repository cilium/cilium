// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"fmt"
	"iter"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/datapath/plugins/types"
)

const (
	deviceNameFlag        = "device"
	podNamespaceFlag      = "namespace"
	podNameFlag           = "pod"
	targetProgramFlag     = "target"
	hookTypeFlag          = "type"
	pluginNameFlag        = "plugin"
	pluginProgramNameFlag = "program"
)

// BindHookStatusFlags binds the set of flags used for commands that display
// hook status.
func BindHookStatusFlags(fs *pflag.FlagSet) {
	fs.String(deviceNameFlag, "", "Filter by device name")
	fs.String(podNamespaceFlag, "", "Filter by pod namespace")
	fs.String(podNameFlag, "", "Filter by pod name")
	fs.String(targetProgramFlag, "", "Filter by target program name")
	fs.String(hookTypeFlag, "", "Filter by hook type (PRE, POST)")
	fs.String(pluginNameFlag, "", "Filter by plugin name")
	fs.String(pluginProgramNameFlag, "", "Filter by hook program name")
}

func hooksStatusCommand(summary string, valueColumnName string, hookStatuses *hookStatusTable, values func(map[string]*types.HookInfo, string) iter.Seq[string]) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: summary,
			Flags:   BindHookStatusFlags,
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			deviceNameFilter, err := s.Flags.GetString(deviceNameFlag)
			if err != nil {
				return nil, err
			}
			podNamespaceFilter, err := s.Flags.GetString(podNamespaceFlag)
			if err != nil {
				return nil, err
			}
			podNameFilter, err := s.Flags.GetString(podNameFlag)
			if err != nil {
				return nil, err
			}
			targetProgramFilter, err := s.Flags.GetString(targetProgramFlag)
			if err != nil {
				return nil, err
			}
			hookTypeFilter, err := s.Flags.GetString(hookTypeFlag)
			if err != nil {
				return nil, err
			}
			pluginNameFilter, err := s.Flags.GetString(pluginNameFlag)
			if err != nil {
				return nil, err
			}
			pluginProgramNameFilter, err := s.Flags.GetString(pluginProgramNameFlag)
			if err != nil {
				return nil, err
			}

			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)

			fmt.Fprintf(tw, "DEVICE\tPOD\tTARGET\tHOOK TYPE\t%s\n", valueColumnName)

			for collHookStatus := range hookStatuses.all() {
				if deviceNameFilter != "" && collHookStatus.AttachmentContext.GetDevice() != deviceNameFilter {
					continue
				}
				if podNamespaceFilter != "" && collHookStatus.AttachmentContext.GetLxc().GetPodInfo().GetNamespace() != podNamespaceFilter {
					continue
				}
				if podNameFilter != "" && collHookStatus.AttachmentContext.GetLxc().GetPodInfo().GetName() != podNameFilter {
					continue
				}

				deviceStr := collHookStatus.AttachmentContext.GetDevice()
				podStr := collHookStatus.PodNamespaceName()

				for targetName := range collHookStatus.OrderedTargetNames() {
					if targetProgramFilter != "" && targetName != targetProgramFilter {
						continue
					}

					targetHookInfo := collHookStatus.Programs[targetName]
					targetProgramInfoStr := fmt.Sprintf("%s (%d)", targetName, targetHookInfo.ID)

					for hookType := range targetHookInfo.OrderedHookTypes() {
						if hookTypeFilter != "" && hookType.String() != hookTypeFilter {
							continue
						}

						hookTypeStr := hookType.String()

						for pluginName := range targetHookInfo.OrderedPlugins(hookType) {
							hook := targetHookInfo.Hooks[hookType][pluginName]
							if pluginNameFilter != "" && pluginName != pluginNameFilter {
								continue
							}
							if pluginProgramNameFilter != "" && hook.ProgramName != pluginProgramNameFilter {
								continue
							}

							for v := range values(targetHookInfo.Hooks[hookType], pluginName) {
								fmt.Fprintf(
									tw, "%s\t%s\t%s\t%s\t%s\n",
									deviceStr,
									podStr,
									targetProgramInfoStr,
									hookTypeStr,
									v,
								)

								deviceStr = ""
								podStr = ""
								targetProgramInfoStr = ""
								hookTypeStr = ""
							}
						}
					}
				}
			}

			tw.Flush()

			return nil, nil
		},
	)
}

func hooksListCommand(hookStatuses *hookStatusTable) script.Cmd {
	return hooksStatusCommand(
		"List active datapath plugin hooks in attachment order",
		"HOOKS",
		hookStatuses,
		func(hooks map[string]*types.HookInfo, pluginName string) iter.Seq[string] {
			return func(yield func(string) bool) {
				yield(fmt.Sprintf("%s:%s (%d)", pluginName, hooks[pluginName].ProgramName, hooks[pluginName].ProgramID))
			}
		},
	)
}

func hooksOrderCommand(hookStatuses *hookStatusTable) script.Cmd {
	return hooksStatusCommand(
		"Explain the order of active datapath plugin hooks",
		"ORDERING CONSTRAINTS",
		hookStatuses,
		func(hooks map[string]*types.HookInfo, pluginName string) iter.Seq[string] {
			program := fmt.Sprintf("%s:%s (%d)", pluginName, hooks[pluginName].ProgramName, hooks[pluginName].ProgramID)

			return func(yield func(string) bool) {
				if len(hooks[pluginName].Constraints) == 0 {
					yield(fmt.Sprintf("%s has no constraints", program))
				}

				for _, c := range hooks[pluginName].Constraints {
					var otherProgram string

					if h := hooks[c.GetPlugin()]; h == nil {
						otherProgram = fmt.Sprintf("%s:? (?)", c.GetPlugin())
					} else {
						otherProgram = fmt.Sprintf("%s:%s (%d)", c.GetPlugin(), h.ProgramName, h.ProgramID)
					}

					var explanation string

					switch c.GetOrder() {
					case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE:
						explanation = fmt.Sprintf("%s is before %s", program, otherProgram)
					case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_AFTER:
						explanation = fmt.Sprintf("%s is after %s", program, otherProgram)
					default:
						explanation = fmt.Sprintf("%s has an unknown constraint", program)
					}

					if !yield(explanation) {
						return
					}
				}
			}
		},
	)
}

func pluginsStatusCommands(hookStatuses *hookStatusTable) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"plugins/hooks/list":  hooksListCommand(hookStatuses),
		"plugins/hooks/order": hooksOrderCommand(hookStatuses),
	})
}
