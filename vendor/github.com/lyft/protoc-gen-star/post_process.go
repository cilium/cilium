package pgs

import (
	"go/format"
	"strings"
)

// A PostProcessor modifies the output of an Artifact before final rendering.
// PostProcessors are only applied to Artifacts created by Modules.
type PostProcessor interface {
	// Match returns true if the PostProcess should be applied to the Artifact.
	// Process is called immediately after Match for the same Artifact.
	Match(a Artifact) bool

	// Process receives the rendered artifact and returns the processed bytes or
	// an error if something goes wrong.
	Process(in []byte) ([]byte, error)
}

type goFmt struct{}

// GoFmt returns a PostProcessor that runs gofmt on any files ending in ".go"
func GoFmt() PostProcessor { return goFmt{} }

func (p goFmt) Match(a Artifact) bool {
	var n string

	switch a := a.(type) {
	case GeneratorFile:
		n = a.Name
	case GeneratorTemplateFile:
		n = a.Name
	case CustomFile:
		n = a.Name
	case CustomTemplateFile:
		n = a.Name
	default:
		return false
	}

	return strings.HasSuffix(n, ".go")
}

func (p goFmt) Process(in []byte) ([]byte, error) { return format.Source(in) }

var _ PostProcessor = goFmt{}
