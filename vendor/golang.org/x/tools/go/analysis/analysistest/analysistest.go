// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package analysistest provides utilities for testing analyzers.
package analysistest

import (
	"bytes"
	"fmt"
	"go/format"
	"go/token"
	"go/types"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/scanner"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/analysis/internal"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/internal/diff"
	"golang.org/x/tools/internal/testenv"
	"golang.org/x/tools/txtar"
)

// WriteFiles is a helper function that creates a temporary directory
// and populates it with a GOPATH-style project using filemap (which
// maps file names to contents). On success it returns the name of the
// directory and a cleanup function to delete it.
//
// TODO(adonovan): provide a newer version that accepts a testing.T,
// calls T.TempDir, and calls T.Fatal on any error, avoiding the need
// to return cleanup or err:
//
//	func WriteFilesToTmp(t *testing.T filemap map[string]string) string
func WriteFiles(filemap map[string]string) (dir string, cleanup func(), err error) {
	gopath, err := os.MkdirTemp("", "analysistest")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(gopath) }

	for name, content := range filemap {
		filename := filepath.Join(gopath, "src", name)
		os.MkdirAll(filepath.Dir(filename), 0777) // ignore error
		if err := os.WriteFile(filename, []byte(content), 0666); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return gopath, cleanup, nil
}

// TestData returns the effective filename of
// the program's "testdata" directory.
// This function may be overridden by projects using
// an alternative build system (such as Blaze) that
// does not run a test in its package directory.
var TestData = func() string {
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		log.Fatal(err)
	}
	return testdata
}

// Testing is an abstraction of a *testing.T.
type Testing interface {
	Errorf(format string, args ...any)
}

// RunWithSuggestedFixes behaves like Run, but additionally applies
// suggested fixes and verifies their output.
//
// It uses golden files, placed alongside each source file, to express
// the desired output: the expected transformation of file example.go
// is specified in file example.go.golden.
//
// Golden files may be of two forms: a plain Go source file, or a
// txtar archive.
//
// A plain Go source file indicates the expected result of applying
// all suggested fixes to the original file.
//
// A txtar archive specifies, in each section, the expected result of
// applying all suggested fixes of a given message to the original
// file; the name of the archive section is the fix's message. In this
// way, the various alternative fixes offered by a single diagnostic
// can be tested independently. Here's an example:
//
//	-- turn into single negation --
//	package pkg
//
//	func fn(b1, b2 bool) {
//		if !b1 { // want `negating a boolean twice`
//			println()
//		}
//	}
//
//	-- remove double negation --
//	package pkg
//
//	func fn(b1, b2 bool) {
//		if b1 { // want `negating a boolean twice`
//			println()
//		}
//	}
//
// # Conflicts
//
// Regardless of the form of the golden file, it is possible for
// multiple fixes to conflict, either because they overlap, or are
// close enough together that the particular diff algorithm cannot
// separate them.
//
// RunWithSuggestedFixes uses a simple three-way merge to accumulate
// fixes, similar to a git merge. The merge algorithm may be able to
// coalesce identical edits, for example duplicate imports of the same
// package. (Bear in mind that this is an editorial decision. In
// general, coalescing identical edits may not be correct: consider
// two statements that increment the same counter.)
//
// If there are conflicts, the test fails. In any case, the
// non-conflicting edits will be compared against the expected output.
// In this situation, we recommend that you increase the textual
// separation between conflicting parts or, if that fails, split
// your tests into smaller parts.
//
// If a diagnostic offers multiple fixes for the same problem, they
// are almost certain to conflict, so in this case you should define
// the expected output using a multi-section txtar file as described
// above.
func RunWithSuggestedFixes(t Testing, dir string, a *analysis.Analyzer, patterns ...string) []*Result {
	results := Run(t, dir, a, patterns...)

	// If the immediate caller of RunWithSuggestedFixes is in
	// x/tools, we apply stricter checks as required by gopls.
	inTools := false
	{
		var pcs [1]uintptr
		n := runtime.Callers(1, pcs[:])
		frames := runtime.CallersFrames(pcs[:n])
		fr, _ := frames.Next()
		if fr.Func != nil && strings.HasPrefix(fr.Func.Name(), "golang.org/x/tools/") {
			inTools = true
		}
	}

	// Process each result (package) separately, matching up the suggested
	// fixes into a diff, which we will compare to the .golden file.  We have
	// to do this per-result in case a file appears in two packages, such as in
	// packages with tests, where mypkg/a.go will appear in both mypkg and
	// mypkg.test.  In that case, the analyzer may suggest the same set of
	// changes to a.go for each package.  If we merge all the results, those
	// changes get doubly applied, which will cause conflicts or mismatches.
	// Validating the results separately means as long as the two analyses
	// don't produce conflicting suggestions for a single file, everything
	// should match up.
	for _, result := range results {
		act := result.Action

		// For each fix, split its edits by file and convert to diff form.
		var (
			// fixEdits: message -> fixes -> filename -> edits
			//
			// TODO(adonovan): this mapping assumes fix.Messages
			// are unique across analyzers, whereas they are only
			// unique within a given Diagnostic.
			fixEdits     = make(map[string][]map[string][]diff.Edit)
			allFilenames = make(map[string]bool)
		)
		for _, diag := range act.Diagnostics {
			// Fixes are validated upon creation in Pass.Report.
			for _, fix := range diag.SuggestedFixes {
				// Assert that lazy fixes have a Category (#65578, #65087).
				if inTools && len(fix.TextEdits) == 0 && diag.Category == "" {
					t.Errorf("missing Diagnostic.Category for SuggestedFix without TextEdits (gopls requires the category for the name of the fix command")
				}

				// Convert edits to diff form.
				// Group fixes by message and file.
				edits := make(map[string][]diff.Edit)
				for _, edit := range fix.TextEdits {
					file := act.Package.Fset.File(edit.Pos)
					allFilenames[file.Name()] = true
					edits[file.Name()] = append(edits[file.Name()], diff.Edit{
						Start: file.Offset(edit.Pos),
						End:   file.Offset(edit.End),
						New:   string(edit.NewText),
					})
				}
				fixEdits[fix.Message] = append(fixEdits[fix.Message], edits)
			}
		}

		merge := func(file, message string, x, y []diff.Edit) []diff.Edit {
			z, ok := diff.Merge(x, y)
			if !ok {
				t.Errorf("in file %s, conflict applying fix %q", file, message)
				return x // discard y
			}
			return z
		}

		// Because the checking is driven by original
		// filenames, there is no way to express that a fix
		// (e.g. extract declaration) creates a new file.
		for _, filename := range slices.Sorted(maps.Keys(allFilenames)) {
			// Read the original file.
			content, err := os.ReadFile(filename)
			if err != nil {
				t.Errorf("error reading %s: %v", filename, err)
				continue
			}

			// check checks that the accumulated edits applied
			// to the original content yield the wanted content.
			check := func(prefix string, accumulated []diff.Edit, want []byte) {
				if err := applyDiffsAndCompare(filename, content, want, accumulated); err != nil {
					t.Errorf("%s: %s", prefix, err)
				}
			}

			// Read the golden file. It may have one of two forms:
			// (1) A txtar archive with one section per fix title,
			//     including all fixes of just that title.
			// (2) The expected output for file.Name after all (?) fixes are applied.
			//     This form requires that no diagnostic has multiple fixes.
			ar, err := txtar.ParseFile(filename + ".golden")
			if err != nil {
				t.Errorf("error reading %s.golden: %v", filename, err)
				continue
			}
			if len(ar.Files) > 0 {
				// Form #1: one archive section per kind of suggested fix.
				if len(ar.Comment) > 0 {
					// Disallow the combination of comment and archive sections.
					t.Errorf("%s.golden has leading comment; we don't know what to do with it", filename)
					continue
				}

				// Each archive section is named for a fix.Message.
				// Accumulate the parts of the fix that apply to the current file,
				// using a simple three-way merge, discarding conflicts,
				// then apply the merged edits and compare to the archive section.
				for _, section := range ar.Files {
					message, want := section.Name, section.Data
					var accumulated []diff.Edit
					for _, fix := range fixEdits[message] {
						accumulated = merge(filename, message, accumulated, fix[filename])
					}
					check(fmt.Sprintf("all fixes of message %q", message), accumulated, want)
				}

			} else {
				// Form #2: all suggested fixes are represented by a single file.
				want := ar.Comment
				var accumulated []diff.Edit
				for _, message := range slices.Sorted(maps.Keys(fixEdits)) {
					for _, fix := range fixEdits[message] {
						accumulated = merge(filename, message, accumulated, fix[filename])
					}
				}
				check("all fixes", accumulated, want)
			}
		}
	}

	return results
}

// applyDiffsAndCompare applies edits to original and compares the results against
// want after formatting both. fileName is use solely for error reporting.
func applyDiffsAndCompare(filename string, original, want []byte, edits []diff.Edit) error {
	// Relativize filename, for tidier errors.
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, filename); err == nil {
			filename = rel
		}
	}

	if len(edits) == 0 {
		return fmt.Errorf("%s: no edits", filename)
	}
	fixedBytes, err := diff.ApplyBytes(original, edits)
	if err != nil {
		return fmt.Errorf("%s: error applying fixes: %v (see possible explanations at RunWithSuggestedFixes)", filename, err)
	}
	fixed, err := format.Source(fixedBytes)
	if err != nil {
		return fmt.Errorf("%s: error formatting resulting source: %v\n%s", filename, err, fixedBytes)
	}

	want, err = format.Source(want)
	if err != nil {
		return fmt.Errorf("%s.golden: error formatting golden file: %v\n%s", filename, err, fixed)
	}

	// Keep error reporting logic below consistent with
	// TestScript in ../internal/checker/fix_test.go!

	unified := func(xlabel, ylabel string, x, y []byte) string {
		x = append(slices.Clip(bytes.TrimSpace(x)), '\n')
		y = append(slices.Clip(bytes.TrimSpace(y)), '\n')
		return diff.Unified(xlabel, ylabel, string(x), string(y))
	}

	if diff := unified(filename+" (fixed)", filename+" (want)", fixed, want); diff != "" {
		return fmt.Errorf("unexpected %s content:\n"+
			"-- original --\n%s\n"+
			"-- fixed --\n%s\n"+
			"-- want --\n%s\n"+
			"-- diff original fixed --\n%s\n"+
			"-- diff fixed want --\n%s",
			filename,
			original,
			fixed,
			want,
			unified(filename+" (original)", filename+" (fixed)", original, fixed),
			diff)
	}
	return nil
}

// Run applies an analysis to the packages denoted by the "go list" patterns.
//
// It loads the packages from the specified
// directory using golang.org/x/tools/go/packages, runs the analysis on
// them, and checks that each analysis emits the expected diagnostics
// and facts specified by the contents of '// want ...' comments in the
// package's source files. It treats a comment of the form
// "//...// want..." or "/*...// want... */" as if it starts at 'want'.
//
// If the directory contains a go.mod file, Run treats it as the root of the
// Go module in which to work. Otherwise, Run treats it as the root of a
// GOPATH-style tree, with package contained in the src subdirectory.
//
// An expectation of a Diagnostic is specified by a string literal
// containing a regular expression that must match the diagnostic
// message. For example:
//
//	fmt.Printf("%s", 1) // want `cannot provide int 1 to %s`
//
// An expectation of a Fact associated with an object is specified by
// 'name:"pattern"', where name is the name of the object, which must be
// declared on the same line as the comment, and pattern is a regular
// expression that must match the string representation of the fact,
// fmt.Sprint(fact). For example:
//
//	func panicf(format string, args interface{}) { // want panicf:"printfWrapper"
//
// Package facts are specified by the name "package" and appear on
// line 1 of the first source file of the package.
//
// A single 'want' comment may contain a mixture of diagnostic and fact
// expectations, including multiple facts about the same object:
//
//	// want "diag" "diag2" x:"fact1" x:"fact2" y:"fact3"
//
// Unexpected diagnostics and facts, and unmatched expectations, are
// reported as errors to the Testing.
//
// Run reports an error to the Testing if loading or analysis failed.
// Run also returns a Result for each package for which analysis was
// attempted, even if unsuccessful. It is safe for a test to ignore all
// the results, but a test may use it to perform additional checks.
func Run(t Testing, dir string, a *analysis.Analyzer, patterns ...string) []*Result {
	if t, ok := t.(testing.TB); ok {
		testenv.NeedsGoPackages(t)
	}

	pkgs, err := loadPackages(dir, patterns...)
	if err != nil {
		t.Errorf("loading %s: %v", patterns, err)
		return nil
	}

	// Print parse and type errors to the test log.
	// (Do not print them to stderr, which would pollute
	// the log in cases where the tests pass.)
	if t, ok := t.(testing.TB); ok && !a.RunDespiteErrors {
		packages.Visit(pkgs, nil, func(pkg *packages.Package) {
			for _, err := range pkg.Errors {
				t.Log(err)
			}
		})
	}

	res, err := checker.Analyze([]*analysis.Analyzer{a}, pkgs, nil)
	if err != nil {
		t.Errorf("Analyze: %v", err)
		return nil
	}

	var results []*Result
	for _, act := range res.Roots {
		if act.Err != nil {
			t.Errorf("error analyzing %s: %v", act, act.Err)
		} else {
			check(t, dir, act)
		}

		// Compute legacy map of facts relating to this package.
		facts := make(map[types.Object][]analysis.Fact)
		for _, objFact := range act.AllObjectFacts() {
			if obj := objFact.Object; obj.Pkg() == act.Package.Types {
				facts[obj] = append(facts[obj], objFact.Fact)
			}
		}
		for _, pkgFact := range act.AllPackageFacts() {
			if pkgFact.Package == act.Package.Types {
				facts[nil] = append(facts[nil], pkgFact.Fact)
			}
		}

		// Construct the legacy result.
		results = append(results, &Result{
			Pass:        internal.Pass(act),
			Diagnostics: act.Diagnostics,
			Facts:       facts,
			Result:      act.Result,
			Err:         act.Err,
			Action:      act,
		})
	}
	return results
}

// A Result holds the result of applying an analyzer to a package.
//
// Facts contains only facts associated with the package and its objects.
//
// This internal type was inadvertently and regrettably exposed
// through a public type alias. It is essentially redundant with
// [checker.Action], but must be retained for compatibility. Clients may
// access the public fields of the Pass but must not invoke any of
// its "verbs", since the pass is already complete.
type Result struct {
	Action *checker.Action

	// legacy fields
	Facts       map[types.Object][]analysis.Fact // nil key => package fact
	Pass        *analysis.Pass
	Diagnostics []analysis.Diagnostic // see Action.Diagnostics
	Result      any                   // see Action.Result
	Err         error                 // see Action.Err
}

// loadPackages uses go/packages to load a specified packages (from source, with
// dependencies) from dir, which is the root of a GOPATH-style project tree.
// loadPackages returns an error if any package had an error, or the pattern
// matched no packages.
func loadPackages(dir string, patterns ...string) ([]*packages.Package, error) {
	env := []string{"GOPATH=" + dir, "GO111MODULE=off", "GOWORK=off"} // GOPATH mode

	// Undocumented module mode. Will be replaced by something better.
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		gowork := filepath.Join(dir, "go.work")
		if _, err := os.Stat(gowork); err != nil {
			gowork = "off"
		}

		env = []string{"GO111MODULE=on", "GOPROXY=off", "GOWORK=" + gowork} // module mode
	}

	// packages.Load loads the real standard library, not a minimal
	// fake version, which would be more efficient, especially if we
	// have many small tests that import, say, net/http.
	// However there is no easy way to make go/packages to consume
	// a list of packages we generate and then do the parsing and
	// typechecking, though this feature seems to be a recurring need.

	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
		packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo |
		packages.NeedDeps | packages.NeedModule
	cfg := &packages.Config{
		Mode:  mode,
		Dir:   dir,
		Tests: true,
		Env:   append(os.Environ(), env...),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}

	// If any named package couldn't be loaded at all
	// (e.g. the Name field is unset), fail fast.
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			return nil, fmt.Errorf("failed to load %q: Errors=%v",
				pkg.PkgPath, pkg.Errors)
		}
	}

	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages matched %s", patterns)
	}
	return pkgs, nil
}

// check inspects an analysis pass on which the analysis has already
// been run, and verifies that all reported diagnostics and facts match
// specified by the contents of "// want ..." comments in the package's
// source files, which must have been parsed with comments enabled.
func check(t Testing, gopath string, act *checker.Action) {
	type key struct {
		file string
		line int
	}

	want := make(map[key][]expectation)

	// processComment parses expectations out of comments.
	processComment := func(filename string, linenum int, text string) {
		text = strings.TrimSpace(text)

		// Any comment starting with "want" is treated
		// as an expectation, even without following whitespace.
		if rest, ok := strings.CutPrefix(text, "want"); ok {
			lineDelta, expects, err := parseExpectations(rest)
			if err != nil {
				t.Errorf("%s:%d: in 'want' comment: %s", filename, linenum, err)
				return
			}
			if expects != nil {
				want[key{filename, linenum + lineDelta}] = expects
			}
		}
	}

	// Extract 'want' comments from parsed Go files.
	for _, f := range act.Package.Syntax {
		for _, cgroup := range f.Comments {
			for _, c := range cgroup.List {

				text := strings.TrimPrefix(c.Text, "//")
				if text == c.Text { // not a //-comment.
					text = strings.TrimPrefix(text, "/*")
					text = strings.TrimSuffix(text, "*/")
				}

				// Hack: treat a comment of the form "//...// want..."
				// or "/*...// want... */
				// as if it starts at 'want'.
				// This allows us to add comments on comments,
				// as required when testing the buildtag analyzer.
				if i := strings.Index(text, "// want"); i >= 0 {
					text = text[i+len("// "):]
				}

				// It's tempting to compute the filename
				// once outside the loop, but it's
				// incorrect because it can change due
				// to //line directives.
				posn := act.Package.Fset.Position(c.Pos())
				filename := sanitize(gopath, posn.Filename)
				processComment(filename, posn.Line, text)
			}
		}
	}

	// Extract 'want' comments from non-Go files.
	// TODO(adonovan): we may need to handle //line directives.
	files := act.Package.OtherFiles

	// Hack: these two analyzers need to extract expectations from
	// all configurations, so include the files are are usually
	// ignored. (This was previously a hack in the respective
	// analyzers' tests.)
	if act.Analyzer.Name == "buildtag" || act.Analyzer.Name == "directive" {
		files = slices.Concat(files, act.Package.IgnoredFiles)
	}

	for _, filename := range files {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Errorf("can't read '// want' comments from %s: %v", filename, err)
			continue
		}
		filename := sanitize(gopath, filename)
		linenum := 0
		for _, line := range strings.Split(string(data), "\n") {
			linenum++

			// Hack: treat a comment of the form "//...// want..."
			// or "/*...// want... */
			// as if it starts at 'want'.
			// This allows us to add comments on comments,
			// as required when testing the buildtag analyzer.
			if i := strings.Index(line, "// want"); i >= 0 {
				line = line[i:]
			}

			if i := strings.Index(line, "//"); i >= 0 {
				line = line[i+len("//"):]
				processComment(filename, linenum, line)
			}
		}
	}

	checkMessage := func(posn token.Position, kind, name, message string) {
		posn.Filename = sanitize(gopath, posn.Filename)
		k := key{posn.Filename, posn.Line}
		expects := want[k]
		var unmatched []string
		for i, exp := range expects {
			if exp.kind == kind && exp.name == name {
				if exp.rx.MatchString(message) {
					// matched: remove the expectation.
					expects[i] = expects[len(expects)-1]
					expects = expects[:len(expects)-1]
					want[k] = expects
					return
				}
				unmatched = append(unmatched, fmt.Sprintf("%#q", exp.rx))
			}
		}
		if unmatched == nil {
			t.Errorf("%v: unexpected %s: %v", posn, kind, message)
		} else {
			t.Errorf("%v: %s %q does not match pattern %s",
				posn, kind, message, strings.Join(unmatched, " or "))
		}
	}

	// Check the diagnostics match expectations.
	for _, f := range act.Diagnostics {
		// TODO(matloob): Support ranges in analysistest.
		posn := act.Package.Fset.Position(f.Pos)
		checkMessage(posn, "diagnostic", "", f.Message)
	}

	// Check the facts match expectations.
	// We check only facts relating to the current package.
	//
	// We report errors in lexical order for determinism.
	// (It's only deterministic within each file, not across files,
	// because go/packages does not guarantee file.Pos is ascending
	// across the files of a single compilation unit.)

	// package facts: reported at start of first file
	for _, pkgFact := range act.AllPackageFacts() {
		if pkgFact.Package == act.Package.Types {
			posn := act.Package.Fset.Position(act.Package.Syntax[0].Pos())
			posn.Line, posn.Column = 1, 1
			checkMessage(posn, "fact", "package", fmt.Sprint(pkgFact))
		}
	}

	// object facts: reported at line of object declaration
	objFacts := act.AllObjectFacts()
	sort.Slice(objFacts, func(i, j int) bool {
		return objFacts[i].Object.Pos() < objFacts[j].Object.Pos()
	})
	for _, objFact := range objFacts {
		if obj := objFact.Object; obj.Pkg() == act.Package.Types {
			posn := act.Package.Fset.Position(obj.Pos())
			checkMessage(posn, "fact", obj.Name(), fmt.Sprint(objFact.Fact))
		}
	}

	// Reject surplus expectations.
	//
	// Sometimes an Analyzer reports two similar diagnostics on a
	// line with only one expectation. The reader may be confused by
	// the error message.
	// TODO(adonovan): print a better error:
	// "got 2 diagnostics here; each one needs its own expectation".
	var surplus []string
	for key, expects := range want {
		for _, exp := range expects {
			err := fmt.Sprintf("%s:%d: no %s was reported matching %#q", key.file, key.line, exp.kind, exp.rx)
			surplus = append(surplus, err)
		}
	}
	sort.Strings(surplus)
	for _, err := range surplus {
		t.Errorf("%s", err)
	}
}

type expectation struct {
	kind string // either "fact" or "diagnostic"
	name string // name of object to which fact belongs, or "package" ("fact" only)
	rx   *regexp.Regexp
}

func (ex expectation) String() string {
	return fmt.Sprintf("%s %s:%q", ex.kind, ex.name, ex.rx) // for debugging
}

// parseExpectations parses the content of a "// want ..." comment
// and returns the expectations, a mixture of diagnostics ("rx") and
// facts (name:"rx").
func parseExpectations(text string) (lineDelta int, expects []expectation, err error) {
	var scanErr string
	sc := new(scanner.Scanner).Init(strings.NewReader(text))
	sc.Error = func(s *scanner.Scanner, msg string) {
		scanErr = msg // e.g. bad string escape
	}
	sc.Mode = scanner.ScanIdents | scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanInts

	scanRegexp := func(tok rune) (*regexp.Regexp, error) {
		if tok != scanner.String && tok != scanner.RawString {
			return nil, fmt.Errorf("got %s, want regular expression",
				scanner.TokenString(tok))
		}
		pattern, _ := strconv.Unquote(sc.TokenText()) // can't fail
		return regexp.Compile(pattern)
	}

	for {
		tok := sc.Scan()
		switch tok {
		case '+':
			tok = sc.Scan()
			if tok != scanner.Int {
				return 0, nil, fmt.Errorf("got +%s, want +Int", scanner.TokenString(tok))
			}
			lineDelta, _ = strconv.Atoi(sc.TokenText())
		case scanner.String, scanner.RawString:
			rx, err := scanRegexp(tok)
			if err != nil {
				return 0, nil, err
			}
			expects = append(expects, expectation{"diagnostic", "", rx})

		case scanner.Ident:
			name := sc.TokenText()
			tok = sc.Scan()
			if tok != ':' {
				return 0, nil, fmt.Errorf("got %s after %s, want ':'",
					scanner.TokenString(tok), name)
			}
			tok = sc.Scan()
			rx, err := scanRegexp(tok)
			if err != nil {
				return 0, nil, err
			}
			expects = append(expects, expectation{"fact", name, rx})

		case scanner.EOF:
			if scanErr != "" {
				return 0, nil, fmt.Errorf("%s", scanErr)
			}
			return lineDelta, expects, nil

		default:
			return 0, nil, fmt.Errorf("unexpected %s", scanner.TokenString(tok))
		}
	}
}

// sanitize removes the GOPATH portion of the filename,
// typically a gnarly /tmp directory, and returns the rest.
func sanitize(gopath, filename string) string {
	prefix := gopath + string(os.PathSeparator) + "src" + string(os.PathSeparator)
	return filepath.ToSlash(strings.TrimPrefix(filename, prefix))
}
