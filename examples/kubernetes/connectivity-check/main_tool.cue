package connectivity_check

import (
	"list"
	"text/tabwriter"
	"tool/cli"
)

objects: [ for v in objectSets for x in v {x}]

objectSets: [
	deployment,
	service,
	egressCNP,
	ingressCNP,
]

globalFlags: "[-t component=<component>] [-t kind=<kind>] [-t name=<name>] [-t topology=<topology>] [-t quarantine=true] [-t type=<tooltype>] [-t traffic=any]"

ccCommand: {
	#flags: {
		component:  "all" | *"default" | "network" | "policy" | "services" | "hostport" | "proxy" @tag(component,short=all|default|network|policy|services|hostport|proxy)
		name:       *"" | string                                                                  @tag(name)
		topology:   *"any" | "single-node"                                                        @tag(topology,short=any|single-node)
		kind:       *"" | "Deployment" | "Service" | "CiliumNetworkPolicy"                        @tag(kind,short=Deployment|Service|CiliumNetworkPolicy)
		type:       *"autocheck" | "tool"                                                         @tag(type,short=autocheck|tool)
		quarantine: *"false" | "true"                                                             @tag(quarantine,short=false|true)
		traffic:    *"any" | "internal" | "external"                                              @tag(traffic,short=any|internal|external)
	}

	task: filterComponent: {
		if #flags.component == "all" {
			resources: objects
		}
		defaultExclusions: [ "hostport-check", "proxy-check"]
		if #flags.component == "default" {
			resources: [ for x in objects if !list.Contains(defaultExclusions, x.metadata.labels.component) {x}]
		}
		if #flags.component != "all" && #flags.component != "default" {
			resources: [ for x in objects if x.metadata.labels.component == "\(#flags.component)-check" {x}]
		}
	}

	task: filterType: {
		resources: [ for x in task.filterComponent.resources if x.metadata.labels.type == #flags.type {x}]
	}

	task: filterQuarantine: {
		resources: [ for x in task.filterType.resources if x.metadata.labels.quarantine == #flags.quarantine {x}]
	}

	task: filterTopology: {
		if #flags.topology == "any" {
			resources: task.filterQuarantine.resources
		}
		if #flags.topology == "single-node" {
			resources: [ for x in task.filterQuarantine.resources if x.metadata.labels.topology != "multi-node" {x}]
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

	task: filterTraffic: {
		if #flags.traffic != "any" {
			resources: [ for x in task.filterName.resources if x.metadata.labels.traffic == #flags.traffic {x}]
		}
		if #flags.traffic == "any" {
			resources: task.filterName.resources
		}
	}

	task: filter: {
		resources: task.filterTraffic.resources
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
