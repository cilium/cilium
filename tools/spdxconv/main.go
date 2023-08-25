// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	usage = `spdxconv is a tool for converting Cilium's copyright and license header
to a SPDX compliant one

Usage:
    spdxconv [package_dir] - provide spdxconv with a absolute path to the go package you'd like to convert.

`
)

var (
	// RegexMap maps an identifying regexp expression
	// with the SPDX string that replaces it.
	RegexpMap = map[*regexp.Regexp]string{
		regexp.MustCompile(`(?m)Apache License, Version 2.0`): "// SPDX-License-Identifier: Apache-2.0",
	}
)

type SPDXConverter struct {
	// the root directory to begin replacing
	// license clauses to spdx clauses
	rootDir string
}

// Walk will begin walking the tree rooted at
// rootDir.
//
// For each .go file it encounters it will parse
// that file's AST and discover the comments.
//
// If the comments indicate a non spdx license
// it will convert it to one and write the file back
// to disk.
func (s *SPDXConverter) Walk() error {
	err := filepath.WalkDir(s.rootDir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		fs := token.NewFileSet()
		astFd, err := parser.ParseFile(fs, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("error while parsing %v: %w", path, err)
		}

		err = s.conv(path, fs, astFd)
		if err != nil {
			return err
		}

		return nil
	})
	return err
}

func (s *SPDXConverter) conv(path string, fset *token.FileSet, f *ast.File) error {
	if len(f.Comments) == 0 {
		return nil
	}
	cg := f.Comments[0]
	if !strings.HasPrefix(cg.List[0].Text, "// Copyright") {
		log.Printf("file %v did not start with a Copyright string. skipping...", path)
		return nil
	}
	var spdx string
	for exp, tmp := range RegexpMap {
		if exp.MatchString(cg.Text()) {
			spdx = tmp
		}
	}
	if spdx == "" {
		log.Printf("could not determine license for %v", path)
		return nil
	}

	copyRight := cg.List[0].Text
	cg.List[0].Text, cg.List[1].Text = spdx, copyRight
	cg.List = cg.List[:2]

	fd, err := os.OpenFile(path, os.O_TRUNC|os.O_RDWR, 0660)
	if err != nil {
		return fmt.Errorf("failed to open original source file for conversion: %w", err)
	}
	defer fd.Close()

	err = format.Node(fd, fset, f)
	if err != nil {
		return fmt.Errorf("failed to write converted file %v: %w", path, err)
	}

	return nil
}

func main() {
	switch {
	case len(os.Args) != 2:
		fmt.Print(usage)
		os.Exit(1)
	case os.Args[1] == "help":
		fmt.Print(usage)
		os.Exit(0)
	}

	path := os.Args[1]
	dir, err := os.Stat(path)
	if err != nil {
		fmt.Printf("provided path %v could not be opened: %v", path, err)
		os.Exit(1)
	}
	if !dir.IsDir() {
		fmt.Println("provided path is not a directory")
		os.Exit(1)
	}

	conv := &SPDXConverter{
		rootDir: path,
	}
	if err := conv.Walk(); err != nil {
		log.Fatal(err.Error())
	}
}
