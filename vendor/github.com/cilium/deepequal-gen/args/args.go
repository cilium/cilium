/*
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Isovalent, Inc.
*/

package args

import (
	"fmt"

	"github.com/spf13/pflag"
)

type Args struct {
	OutputFile   string
	OutputBase   string
	BoundingDirs []string // Only deal with types rooted under these dirs.
	GoHeaderFile string
}

// New returns default arguments for the generator.
func New() *Args {
	return &Args{}
}

// AddFlags add the generator flags to the flag set.
func (args *Args) AddFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&args.OutputFile, "output-file", "O", "generated.deepequal.go",
		"the name of the file to be generated")
	fs.StringVarP(&args.OutputBase, "output-base", "o", args.OutputBase, "Output base; defaults to $GOPATH/src/ or ./ if $GOPATH is not set.")
	fs.StringSliceVar(&args.BoundingDirs, "bounding-dirs", args.BoundingDirs,
		"Comma-separated list of import paths which bound the types for which deep-copies will be generated.")
	fs.StringVarP(&args.GoHeaderFile, "go-header-file", "h", args.GoHeaderFile, "File containing boilerplate header text. The string YEAR will be replaced with the current 4-digit year.")
}

// Validate checks the given arguments.
func (args *Args) Validate() error {
	if len(args.OutputFile) == 0 {
		return fmt.Errorf("--output-file must be specified")
	}
	return nil
}
