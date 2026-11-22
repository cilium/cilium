// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/scanner"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"

	"golang.org/x/telemetry/counter"
	"golang.org/x/tools/internal/diff"
	"golang.org/x/tools/internal/gocommand"
	"golang.org/x/tools/internal/imports"
)

var (
	// main operation modes
	list   = flag.Bool("l", false, "list files whose formatting differs from goimport's")
	write  = flag.Bool("w", false, "write result to (source) file instead of stdout")
	doDiff = flag.Bool("d", false, "display diffs instead of rewriting files")
	srcdir = flag.String("srcdir", "", "choose imports as if source code is from `dir`. When operating on a single file, dir may instead be the complete file name.")

	verbose bool // verbose logging

	cpuProfile     = flag.String("cpuprofile", "", "CPU profile output")
	memProfile     = flag.String("memprofile", "", "memory profile output")
	memProfileRate = flag.Int("memrate", 0, "if > 0, sets runtime.MemProfileRate")

	options = &imports.Options{
		TabWidth:  8,
		TabIndent: true,
		Comments:  true,
		Fragment:  true,
		Env: &imports.ProcessEnv{
			GocmdRunner: &gocommand.Runner{},
		},
	}
	exitCode = 0
)

func init() {
	flag.BoolVar(&options.AllErrors, "e", false, "report all errors (not just the first 10 on different lines)")
	flag.StringVar(&options.LocalPrefix, "local", "", "put imports beginning with this string after 3rd-party packages; comma-separated list")
	flag.BoolVar(&options.FormatOnly, "format-only", false, "if true, don't fix imports and only format. In this mode, goimports is effectively gofmt, with the addition that imports are grouped into sections.")
}

func report(err error) {
	scanner.PrintError(os.Stderr, err)
	exitCode = 2
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: goimports [flags] [path ...]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func isGoFile(d fs.DirEntry) bool {
	// ignore non-Go files
	name := d.Name()
	return !d.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
}

// argumentType is which mode goimports was invoked as.
type argumentType int

const (
	// fromStdin means the user is piping their source into goimports.
	fromStdin argumentType = iota

	// singleArg is the common case from editors, when goimports is run on
	// a single file.
	singleArg

	// multipleArg is when the user ran "goimports file1.go file2.go"
	// or ran goimports on a directory tree.
	multipleArg
)

func processFile(filename string, in io.Reader, out io.Writer, argType argumentType) error {
	opt := options
	if argType == fromStdin {
		nopt := *options
		nopt.Fragment = true
		opt = &nopt
	}

	if in == nil {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	src, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	target := filename
	if *srcdir != "" {
		// Determine whether the provided -srcdirc is a directory or file
		// and then use it to override the target.
		//
		// See https://github.com/dominikh/go-mode.el/issues/146
		if isFile(*srcdir) {
			if argType == multipleArg {
				return errors.New("-srcdir value can't be a file when passing multiple arguments or when walking directories")
			}
			target = *srcdir
		} else if argType == singleArg && strings.HasSuffix(*srcdir, ".go") && !isDir(*srcdir) {
			// For a file which doesn't exist on disk yet, but might shortly.
			// e.g. user in editor opens $DIR/newfile.go and newfile.go doesn't yet exist on disk.
			// The goimports on-save hook writes the buffer to a temp file
			// first and runs goimports before the actual save to newfile.go.
			// The editor's buffer is named "newfile.go" so that is passed to goimports as:
			//      goimports -srcdir=/gopath/src/pkg/newfile.go /tmp/gofmtXXXXXXXX.go
			// and then the editor reloads the result from the tmp file and writes
			// it to newfile.go.
			target = *srcdir
		} else {
			// Pretend that file is from *srcdir in order to decide
			// visible imports correctly.
			target = filepath.Join(*srcdir, filepath.Base(filename))
		}
	}

	res, err := imports.Process(target, src, opt)
	if err != nil {
		return err
	}

	if !bytes.Equal(src, res) {
		// formatting has changed
		if *list {
			fmt.Fprintln(out, filename)
		}
		if *write {
			if argType == fromStdin {
				// filename is "<standard input>"
				return errors.New("can't use -w on stdin")
			}
			// On Windows, we need to re-set the permissions from the file. See golang/go#38225.
			var perms os.FileMode
			if fi, err := os.Stat(filename); err == nil {
				perms = fi.Mode() & os.ModePerm
			}
			if err := os.WriteFile(filename, res, perms); err != nil {
				return err
			}
		}
		if *doDiff {
			if argType == fromStdin {
				filename = "stdin.go" // because <standard input>.orig looks silly
			}
			// Always print filepath with slash separator.
			filename = filepath.ToSlash(filename)
			// Keep a tab after filenames so diff readers can parse names with spaces.
			data := diff.Unified(filename+".orig\t", filename+"\t", string(src), string(res))
			_, err := fmt.Fprintf(out, "diff -u %s %s\n%s", filename+".orig", filename, data)
			return err
		}
	}

	if !*list && !*write && !*doDiff {
		_, err := out.Write(res)
		return err
	}

	return nil
}

func visitFile(path string, d fs.DirEntry, err error) error {
	if err == nil && isGoFile(d) {
		err = processFile(path, nil, os.Stdout, multipleArg)
	}
	if err != nil {
		report(err)
	}
	return nil
}

func walkDir(path string) {
	filepath.WalkDir(path, visitFile)
}

func main() {
	// Measure how many people still use goimports.
	// (See https://go.dev/issue/78671 for one.)
	counter.Open()
	counter.Inc("tools/cmd:goimports")
	runtime.GOMAXPROCS(runtime.NumCPU())

	// call gofmtMain in a separate function
	// so that it can use defer and have them
	// run before the exit.
	gofmtMain()
	if !testing.Testing() {
		os.Exit(exitCode)
	}
}

// parseFlags parses command line flags and returns the paths to process.
// It's a var so that custom implementations can replace it in other files.
var parseFlags = func() []string {
	flag.BoolVar(&verbose, "v", false, "verbose logging")

	flag.Parse()
	return flag.Args()
}

func bufferedFileWriter(dest string) (w io.Writer, close func()) {
	f, err := os.Create(dest)
	if err != nil {
		log.Fatal(err)
	}
	bw := bufio.NewWriter(f)
	return bw, func() {
		if err := bw.Flush(); err != nil {
			log.Fatalf("error flushing %v: %v", dest, err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}

func gofmtMain() {
	flag.Usage = usage
	paths := parseFlags()

	if *cpuProfile != "" {
		bw, flush := bufferedFileWriter(*cpuProfile)
		pprof.StartCPUProfile(bw)
		defer flush()
		defer pprof.StopCPUProfile()
	}
	// doTrace is a conditionally compiled wrapper around runtime/trace. It is
	// used to allow goimports to compile under gccgo, which does not support
	// runtime/trace. See https://golang.org/issue/15544.
	defer doTrace()()
	if *memProfileRate > 0 {
		runtime.MemProfileRate = *memProfileRate
		bw, flush := bufferedFileWriter(*memProfile)
		defer func() {
			runtime.GC() // materialize all statistics
			if err := pprof.WriteHeapProfile(bw); err != nil {
				log.Fatal(err)
			}
			flush()
		}()
	}

	if verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		options.Env.Logf = log.Printf
	}
	if options.TabWidth < 0 {
		fmt.Fprintf(os.Stderr, "negative tabwidth %d\n", options.TabWidth)
		exitCode = 2
		return
	}

	if len(paths) == 0 {
		if err := processFile("<standard input>", os.Stdin, os.Stdout, fromStdin); err != nil {
			report(err)
		}
		return
	}

	argType := singleArg
	if len(paths) > 1 {
		argType = multipleArg
	}

	for _, path := range paths {
		switch dir, err := os.Stat(path); {
		case err != nil:
			report(err)
		case dir.IsDir():
			walkDir(path)
		default:
			if err := processFile(path, nil, os.Stdout, argType); err != nil {
				report(err)
			}
		}
	}
}

// isFile reports whether name is a file.
func isFile(name string) bool {
	fi, err := os.Stat(name)
	return err == nil && fi.Mode().IsRegular()
}

// isDir reports whether name is a directory.
func isDir(name string) bool {
	fi, err := os.Stat(name)
	return err == nil && fi.IsDir()
}
