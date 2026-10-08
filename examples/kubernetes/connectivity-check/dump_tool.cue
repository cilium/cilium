package connectivity_check

import (
	"encoding/yaml"
	"tool/cli"
)

command: dump: ccCommand & {
	usage: "cue \(globalFlags) dump"
	short: "Generate connectivity-check YAMLs from the cuelang scripts"

	task: print: cli.Print & {
		text: "---\n" + yaml.MarshalStream(task.filter.resources)
	}
}
