// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

func main() {
	verbose := flag.Bool("v", false, "also list benign collisions")
	flag.Parse()
	dir := ".github/workflows"
	if flag.NArg() > 0 {
		dir = flag.Arg(0)
	}

	var paths []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		matches, _ := filepath.Glob(filepath.Join(dir, pat))
		paths = append(paths, matches...)
	}

	filesByName := map[string]map[string]bool{}
	isWorkflowName := map[string]bool{}
	scopes := map[string]scope{}
	add := func(name, file string) {
		if filesByName[name] == nil {
			filesByName[name] = map[string]bool{}
		}
		filesByName[name][file] = true
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		var wf workflow
		if err := yaml.Unmarshal(data, &wf); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", path, err)
			os.Exit(2)
		}
		file := filepath.Join(".github/workflows", filepath.Base(path))
		scopes[file] = branchScope(wf.On)
		if wf.Name != "" {
			add(wf.Name, file)
			isWorkflowName[wf.Name] = true
		}
		for _, job := range wf.Jobs {
			if job.Name != "" {
				add(job.Name, file)
			}
		}
	}

	status := 0
	for _, name := range slices.Sorted(maps.Keys(filesByName)) {
		// A collision needs two or more files and the name must be a workflow
		// name, not only a job name
		if len(filesByName[name]) < 2 || !isWorkflowName[name] {
			continue
		}
		files := slices.Sorted(maps.Keys(filesByName[name]))
		if neverRunTogether(files, scopes) {
			if *verbose {
				report(fmt.Sprintf("Benign collision on %q across workflows with disjoint branch triggers", name), files)
			}
			continue
		}
		report(fmt.Sprintf("Ambiguous check context %q produced by more than one workflow that can run for the same pull request", name), files)
		status = 1
	}
	os.Exit(status)
}

type workflow struct {
	Name string    `yaml:"name"`
	On   yaml.Node `yaml:"on"`
	Jobs map[string]struct {
		Name string `yaml:"name"`
	} `yaml:"jobs"`
}

type scope struct {
	closed   bool
	includes []string
	excludes []string
}

func branchScope(on yaml.Node) scope {
	if on.Kind != yaml.MappingNode {
		return scope{}
	}
	var events map[string]struct {
		Branches       []string `yaml:"branches"`
		BranchesIgnore []string `yaml:"branches-ignore"`
	}
	if on.Decode(&events) != nil {
		return scope{}
	}

	open := false
	var includes, excludes []string
	addExclude := func(b string) {
		if !isGlob(b) {
			excludes = append(excludes, b)
		}
	}
	for event, filter := range events {
		switch event {
		case "workflow_call":
		case "pull_request", "pull_request_target", "push":
			if len(filter.Branches) == 0 && len(filter.BranchesIgnore) == 0 {
				open = true
			}
			for _, b := range filter.Branches {
				switch {
				case strings.HasPrefix(b, "!"):
					addExclude(strings.TrimPrefix(b, "!"))
				case isGlob(b):
					open = true
				default:
					includes = append(includes, b)
				}
			}
			if len(filter.BranchesIgnore) > 0 {
				open = true
				for _, b := range filter.BranchesIgnore {
					addExclude(b)
				}
			}
		default:
			open = true
		}
	}
	return scope{closed: !open && len(includes) > 0, includes: includes, excludes: excludes}
}

func isGlob(s string) bool { return strings.ContainsAny(s, "*?[]") }

// disjoint reports whether two scopes can never match the same base branch
func disjoint(a, b scope) bool {
	return (a.closed && subset(a.includes, b.excludes)) ||
		(b.closed && subset(b.includes, a.excludes)) ||
		(a.closed && b.closed && !intersects(a.includes, b.includes))
}

func neverRunTogether(files []string, scopes map[string]scope) bool {
	for i := range files {
		for j := i + 1; j < len(files); j++ {
			if !disjoint(scopes[files[i]], scopes[files[j]]) {
				return false
			}
		}
	}
	return true
}

func subset(xs, ys []string) bool {
	for _, x := range xs {
		if !slices.Contains(ys, x) {
			return false
		}
	}
	return true
}

func intersects(xs, ys []string) bool {
	for _, x := range xs {
		if slices.Contains(ys, x) {
			return true
		}
	}
	return false
}

func report(headline string, files []string) {
	fmt.Println(headline)
	for _, f := range files {
		fmt.Printf("  %s\n", f)
	}
}
