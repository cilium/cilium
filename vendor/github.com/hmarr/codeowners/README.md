# codeowners

![build](https://github.com/hmarr/codeowners/workflows/build/badge.svg)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/hmarr/codeowners)](https://pkg.go.dev/github.com/hmarr/codeowners)

A CLI and Go library for GitHub's [CODEOWNERS file](https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-code-owners#codeowners-syntax).

## Command line tool

The `codeowners` CLI identifies the owners for files in a local repository or directory.

### Installation

If you're on macOS, you can install the CLI from the [homebrew tap](https://github.com/hmarr/homebrew-tap#codeowners).

```console
$ brew tap hmarr/tap
$ brew install codeowners
```

Otherwise, grab a binary from the [releases page](https://github.com/hmarr/codeowners/releases) or install from source with `go install`:

```console
$ go install github.com/hmarr/codeowners/cmd/codeowners@latest
```

### Usage

By default, the command line tool will walk the directory tree, printing the code owners of any files that are found.

```console
$ codeowners --help
usage: codeowners <path>...
  -f, --file string     CODEOWNERS file path
  -h, --help            show this help message
  -o, --owner strings   filter results by owner
  -u, --unowned         only show unowned files (can be combined with -o)

$ ls
CODEOWNERS       DOCUMENTATION.md README.md        example.go       example_test.go

$ cat CODEOWNERS
*.go       @example/go-engineers
*.md       @example/docs-writers
README.md  product-manager@example.com

$ codeowners
CODEOWNERS                           (unowned)
README.md                            product-manager@example.com
example_test.go                      @example/go-engineers
example.go                           @example/go-engineers
DOCUMENTATION.md                     @example/docs-writers
```

To limit the files the tool looks at, provide one or more paths as arguments.

```console
$ codeowners *.md
README.md                            product-manager@example.com
DOCUMENTATION.md                     @example/docs-writers
```

Pass the `--owner` flag to filter results by a specific owner.

```console
$ codeowners -o @example/go-engineers
example_test.go                      @example/go-engineers
example.go                           @example/go-engineers
```

Pass the `--unowned` flag to only show unowned files.

```console
$ codeowners -u
CODEOWNERS                           (unowned)
```

## Go library

A package for parsing CODEOWNERS files and matching files to owners.

### Installation

```console
$ go get github.com/hmarr/codeowners
```

### Usage

Full documentation is available at [pkg.go.dev](https://pkg.go.dev/github.com/hmarr/codeowners).

Here's a quick example to get you started:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hmarr/codeowners"
)

func main() {
	file, err := os.Open("CODEOWNERS")
	if err != nil {
		log.Fatal(err)
	}

	ruleset, err := codeowners.ParseFile(file)
	if err != nil {
		log.Fatal(err)
	}

	rule, err := ruleset.Match("path/to/file")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Owners: %v\n", rule.Owners)
}
```
