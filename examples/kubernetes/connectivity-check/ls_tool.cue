package connectivity_check

import (
	"text/tabwriter"
	"tool/cli"
)

command: ls: ccCommand & {
	usage: "cue \(globalFlags) ls"
	short: "List connectivity-check resources specified in this directory"

	task: print: cli.Print & {
		header: ["KIND   \tCOMPONENT   \tTOPOLOGY   \tNAME", ...]
		text: tabwriter.Write(header + [
			for x in task.filter.resources {
				"\(x.kind)  \t\(x.metadata.labels.component)  \t\(x.metadata.labels.topology)  \t\(x.metadata.name)"
			},
		])
	}
}
