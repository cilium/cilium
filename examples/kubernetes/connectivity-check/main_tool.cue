package connectivity_check

import (
	"text/tabwriter"
	"tool/cli"
)

objects: [ for v in objectSets for x in v {x}]

objectSets: [
	deployment,
	service,
	egressCNP,
]

globalFlags: "[-t component=<component>] [-t kind=<kind>] [-t name=<name>] [-t topology=<topology>]"

ccCommand: {
	#flags: {
		component: "all" | *"default" | "network" | "policy" | "services" | "hostport" | "proxy" @tag(component,short=all|default|network|policy|services|hostport|proxy)
		name:      *"" | string                                                                  @tag(name)
		topology:  *"any" | "single-node"                                                        @tag(topology,short=any|single-node)
		kind:      *"" | "Deployment" | "Service" | "CiliumNetworkPolicy"                        @tag(kind,short=Deployment|Service|CiliumNetworkPolicy)
	}

	task: filterComponent: {
		if #flags.component == "all" {
			resources: objects
		}
		if #flags.component == "default" {
			resources: [ for x in objects if x.metadata.labels.component != "hostport-check" {x}]
		}
		if #flags.component != "all" && #flags.component != "default" {
			resources: [ for x in objects if x.metadata.labels.component == "\(#flags.component)-check" {x}]
		}
	}

	task: filterTopology: {
		if #flags.topology == "any" {
			resources: task.filterComponent.resources
		}
		if #flags.topology == "single-node" {
			resources: [ for x in task.filterComponent.resources if x.metadata.labels.topology != "multi-node" {x}]
		}
	}

	task: filterKind: {
		if #flags.kind == "" {
			resources: task.filterTopology.resources
		}
		if #flags.kind != "" {
			resources: [ for x in task.filterTopology.resources if x.kind == #flags.kind {x}]
		}
	}

	task: filterName: {
		if #flags.name == "" {
			resources: task.filterKind.resources
		}
		if #flags.name != "" {
			resources: [ for x in task.filterKind.resources if x.metadata.labels.name == #flags.name {x}]
		}
	}

	task: filter: {
		resources: task.filterName.resources
	}
}

command: help: ccCommand & {
	usage: "cue \(globalFlags) <command>"
	short: "List connectivity-check resources specified in this directory"

	task: print: cli.Print & {
		helpText: [
			short,
			"",
			"Usage:",
			"  \(usage)",
			"",
			"Available Commands:",
			"  dump\t\t\t\(command.dump.short)",
			"  ls  \t\t\t\(command.ls.short)",
		]
		text: tabwriter.Write(helpText)
	}
}
