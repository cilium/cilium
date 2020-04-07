package pgsgo

import (
	"go/format"
	"strings"

	pgs "github.com/lyft/protoc-gen-star"
)

type goFmt struct{}

// GoFmt returns a PostProcessor that runs gofmt on any files ending in ".go"
func GoFmt() pgs.PostProcessor { return goFmt{} }

func (p goFmt) Match(a pgs.Artifact) bool {
	var n string

	switch a := a.(type) {
	case pgs.GeneratorFile:
		n = a.Name
	case pgs.GeneratorTemplateFile:
		n = a.Name
	case pgs.CustomFile:
		n = a.Name
	case pgs.CustomTemplateFile:
		n = a.Name
	default:
		return false
	}

	return strings.HasSuffix(n, ".go")
}

func (p goFmt) Process(in []byte) ([]byte, error) { return format.Source(in) }

var _ pgs.PostProcessor = goFmt{}
