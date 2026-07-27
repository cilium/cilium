// Package codeowners is a library for working with CODEOWNERS files.
//
// CODEOWNERS files map gitignore-style path patterns to sets of owners, which
// may be GitHub users, GitHub teams, or email addresses. This library parses
// the CODEOWNERS file format into rulesets, which may then be used to determine
// the ownership of files.
//
// Usage
//
// To find the owner of a given file, parse a CODEOWNERS file and call Match()
// on the resulting ruleset.
//  ruleset, err := codeowners.ParseFile(file)
//  if err != nil {
//  	log.Fatal(err)
//  }
//
//  rule, err := ruleset.Match("path/to/file")
//  if err != nil {
//  	log.Fatal(err)
//  }
//
// Command line interface
//
// A command line interface is also available in the cmd/codeowners package.
// When run, it will walk the directory tree showing the code owners for each
// file encountered. The help flag lists available options.
//
//  $ codeowners --help
package codeowners

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LoadFileFromStandardLocation loads and parses a CODEOWNERS file at one of the
// standard locations for CODEOWNERS files (./, .github/, docs/). If run from a
// git repository, all paths are relative to the repository root.
func LoadFileFromStandardLocation() (Ruleset, error) {
	path := findFileAtStandardLocation()
	if path == "" {
		return nil, fmt.Errorf("could not find CODEOWNERS file at any of the standard locations")
	}
	return LoadFile(path)
}

// LoadFile loads and parses a CODEOWNERS file at the path specified.
func LoadFile(path string) (Ruleset, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ParseFile(f)
}

// findFileAtStandardLocation loops through the standard locations for
// CODEOWNERS files (./, .github/, docs/), and returns the first place a
// CODEOWNERS file is found. If run from a git repository, all paths are
// relative to the repository root.
func findFileAtStandardLocation() string {
	pathPrefix := ""
	repoRoot, inRepo := findRepositoryRoot()
	if inRepo {
		pathPrefix = repoRoot
	}

	for _, path := range []string{"CODEOWNERS", ".github/CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS"} {
		fullPath := filepath.Join(pathPrefix, path)
		if fileExists(fullPath) {
			return fullPath
		}
	}
	return ""
}

// fileExist checks if a normal file exists at the path specified.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// findRepositoryRoot returns the path to the root of the git repository, if
// we're currently in one. If we're not in a git repository, the boolean return
// value is false.
func findRepositoryRoot() (string, bool) {
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(output)), true
}

// Ruleset is a collection of CODEOWNERS rules.
type Ruleset []Rule

// Match finds the last rule in the ruleset that matches the path provided. When
// determining the ownership of a file using CODEOWNERS, order matters, and the
// last matching rule takes precedence.
func (r Ruleset) Match(path string) (*Rule, error) {
	for i := len(r) - 1; i >= 0; i-- {
		rule := &r[i]
		match, err := rule.Match(path)
		if match || err != nil {
			return rule, err
		}
	}
	return nil, nil
}

// Rule is a CODEOWNERS rule that maps a gitignore-style path pattern to a set
// of owners.
type Rule struct {
	Owners     []Owner
	Comment    string
	LineNumber int
	pattern    pattern
}

// RawPattern returns the rule's gitignore-style path pattern.
func (r Rule) RawPattern() string {
	return r.pattern.pattern
}

// Match tests whether the provided matches the rule's pattern.
func (r Rule) Match(path string) (bool, error) {
	return r.pattern.match(path)
}

const (
	// EmailOwner is the owner type for email addresses.
	EmailOwner string = "email"
	// TeamOwner is the owner type for GitHub teams.
	TeamOwner string = "team"
	// UsernameOwner is the owner type for GitHub usernames.
	UsernameOwner string = "username"
)

// Owner represents an owner found in a rule.
type Owner struct {
	// Value is the name of the owner: the email addres, team name, or username.
	Value string
	// Type will be one of 'email', 'team', or 'username'.
	Type string
}

// String returns a string representation of the owner. For email owners, it
// simply returns the email address. For user and team owners it prepends an '@'
// to the owner.
func (o Owner) String() string {
	if o.Type == EmailOwner {
		return o.Value
	}
	return "@" + o.Value
}
