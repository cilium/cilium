package lintcmd

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"go/build"
	"go/token"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"honnef.co/go/tools/analysis/lint"
	"honnef.co/go/tools/config"
	"honnef.co/go/tools/go/loader"
	"honnef.co/go/tools/internal/cache"
	"honnef.co/go/tools/lintcmd/runner"
	"honnef.co/go/tools/lintcmd/version"
	"honnef.co/go/tools/unused"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
)

type ignore interface {
	Match(p problem) bool
}

type lineIgnore struct {
	File    string
	Line    int
	Checks  []string
	Matched bool
	Pos     token.Position
}

func (li *lineIgnore) Match(p problem) bool {
	pos := p.Position
	if pos.Filename != li.File || pos.Line != li.Line {
		return false
	}
	for _, c := range li.Checks {
		if m, _ := filepath.Match(c, p.Category); m {
			li.Matched = true
			return true
		}
	}
	return false
}

func (li *lineIgnore) String() string {
	matched := "not matched"
	if li.Matched {
		matched = "matched"
	}
	return fmt.Sprintf("%s:%d %s (%s)", li.File, li.Line, strings.Join(li.Checks, ", "), matched)
}

type fileIgnore struct {
	File   string
	Checks []string
}

func (fi *fileIgnore) Match(p problem) bool {
	if p.Position.Filename != fi.File {
		return false
	}
	for _, c := range fi.Checks {
		if m, _ := filepath.Match(c, p.Category); m {
			return true
		}
	}
	return false
}

type severity uint8

const (
	severityError severity = iota
	severityWarning
	severityIgnored
)

func (s severity) String() string {
	switch s {
	case severityError:
		return "error"
	case severityWarning:
		return "warning"
	case severityIgnored:
		return "ignored"
	default:
		return fmt.Sprintf("Severity(%d)", s)
	}
}

// problem represents a problem in some source code.
type problem struct {
	runner.Diagnostic
	Severity severity
}

func (p problem) equal(o problem) bool {
	return p.Position == o.Position &&
		p.End == o.End &&
		p.Message == o.Message &&
		p.Category == o.Category &&
		p.Severity == o.Severity
}

func (p *problem) String() string {
	return fmt.Sprintf("%s (%s)", p.Message, p.Category)
}

// A linter lints Go source code.
type linter struct {
	Checkers []*analysis.Analyzer
	Config   config.Config
	Runner   *runner.Runner
}

func failed(res runner.Result) []problem {
	var problems []problem

	for _, e := range res.Errors {
		switch e := e.(type) {
		case packages.Error:
			msg := e.Msg
			if len(msg) != 0 && msg[0] == '\n' {
				// TODO(dh): See https://github.com/golang/go/issues/32363
				msg = msg[1:]
			}

			var posn token.Position
			if e.Pos == "" {
				// Under certain conditions (malformed package
				// declarations, multiple packages in the same
				// directory), go list emits an error on stderr
				// instead of JSON. Those errors do not have
				// associated position information in
				// go/packages.Error, even though the output on
				// stderr may contain it.
				if p, n, err := parsePos(msg); err == nil {
					if abs, err := filepath.Abs(p.Filename); err == nil {
						p.Filename = abs
					}
					posn = p
					msg = msg[n+2:]
				}
			} else {
				var err error
				posn, _, err = parsePos(e.Pos)
				if err != nil {
					panic(fmt.Sprintf("internal error: %s", e))
				}
			}
			p := problem{
				Diagnostic: runner.Diagnostic{
					Position: posn,
					Message:  msg,
					Category: "compile",
				},
				Severity: severityError,
			}
			problems = append(problems, p)
		case error:
			p := problem{
				Diagnostic: runner.Diagnostic{
					Position: token.Position{},
					Message:  e.Error(),
					Category: "compile",
				},
				Severity: severityError,
			}
			problems = append(problems, p)
		}
	}

	return problems
}

type unusedKey struct {
	pkgPath string
	base    string
	line    int
	name    string
}

type unusedPair struct {
	key unusedKey
	obj unused.SerializedObject
}

func success(allowedChecks map[string]bool, res runner.ResultData) []problem {
	diags := res.Diagnostics
	var problems []problem
	for _, diag := range diags {
		if !allowedChecks[diag.Category] {
			continue
		}
		problems = append(problems, problem{Diagnostic: diag})
	}
	return problems
}

func filterIgnored(problems []problem, res runner.ResultData, allowedAnalyzers map[string]bool) ([]problem, error) {
	couldveMatched := func(ig *lineIgnore) bool {
		for _, c := range ig.Checks {
			if c == "U1000" {
				// We never want to flag ignores for U1000,
				// because U1000 isn't local to a single
				// package. For example, an identifier may
				// only be used by tests, in which case an
				// ignore would only fire when not analyzing
				// tests. To avoid spurious "useless ignore"
				// warnings, just never flag U1000.
				return false
			}

			// Even though the runner always runs all analyzers, we
			// still only flag unmatched ignores for the set of
			// analyzers the user has expressed interest in. That way,
			// `staticcheck -checks=SA1000` won't complain about an
			// unmatched ignore for an unrelated check.
			if allowedAnalyzers[c] {
				return true
			}
		}

		return false
	}

	ignores, moreProblems := parseDirectives(res.Directives)

	for _, ig := range ignores {
		for i := range problems {
			p := &problems[i]
			if ig.Match(*p) {
				p.Severity = severityIgnored
			}
		}

		if ig, ok := ig.(*lineIgnore); ok && !ig.Matched && couldveMatched(ig) {
			p := problem{
				Diagnostic: runner.Diagnostic{
					Position: ig.Pos,
					Message:  "this linter directive didn't match anything; should it be removed?",
					Category: "staticcheck",
				},
			}
			moreProblems = append(moreProblems, p)
		}
	}

	return append(problems, moreProblems...), nil
}

func newLinter(cfg config.Config) (*linter, error) {
	r, err := runner.New(cfg)
	if err != nil {
		return nil, err
	}
	return &linter{
		Config: cfg,
		Runner: r,
	}, nil
}

func (l *linter) SetGoVersion(n int) {
	l.Runner.GoVersion = n
}

func (l *linter) Lint(cfg *packages.Config, patterns []string) (problems []problem, warnings []string, err error) {
	results, err := l.Runner.Run(cfg, l.Checkers, patterns)
	if err != nil {
		return nil, nil, err
	}

	if len(results) == 0 && err == nil {
		// TODO(dh): emulate Go's behavior more closely once we have
		// access to go list's Match field.
		for _, pattern := range patterns {
			fmt.Fprintf(os.Stderr, "warning: %q matched no packages\n", pattern)
		}
	}

	analyzerNames := make([]string, len(l.Checkers))
	for i, a := range l.Checkers {
		analyzerNames[i] = a.Name
	}

	used := map[unusedKey]bool{}
	var unuseds []unusedPair
	for _, res := range results {
		if len(res.Errors) > 0 && !res.Failed {
			panic("package has errors but isn't marked as failed")
		}
		if res.Failed {
			problems = append(problems, failed(res)...)
		} else {
			if res.Skipped {
				warnings = append(warnings, fmt.Sprintf("skipped package %s because it is too large", res.Package))
				continue
			}

			if !res.Initial {
				continue
			}

			allowedAnalyzers := filterAnalyzerNames(analyzerNames, res.Config.Checks)
			resd, err := res.Load()
			if err != nil {
				return nil, nil, err
			}
			ps := success(allowedAnalyzers, resd)
			filtered, err := filterIgnored(ps, resd, allowedAnalyzers)
			if err != nil {
				return nil, nil, err
			}
			problems = append(problems, filtered...)

			for _, obj := range resd.Unused.Used {
				// FIXME(dh): pick the object whose filename does not include $GOROOT
				key := unusedKey{
					pkgPath: res.Package.PkgPath,
					base:    filepath.Base(obj.Position.Filename),
					line:    obj.Position.Line,
					name:    obj.Name,
				}
				used[key] = true
			}

			if allowedAnalyzers["U1000"] {
				for _, obj := range resd.Unused.Unused {
					key := unusedKey{
						pkgPath: res.Package.PkgPath,
						base:    filepath.Base(obj.Position.Filename),
						line:    obj.Position.Line,
						name:    obj.Name,
					}
					unuseds = append(unuseds, unusedPair{key, obj})
					if _, ok := used[key]; !ok {
						used[key] = false
					}
				}
			}
		}
	}

	for _, uo := range unuseds {
		if used[uo.key] {
			continue
		}
		if uo.obj.InGenerated {
			continue
		}
		problems = append(problems, problem{
			Diagnostic: runner.Diagnostic{
				Position: uo.obj.DisplayPosition,
				Message:  fmt.Sprintf("%s %s is unused", uo.obj.Kind, uo.obj.Name),
				Category: "U1000",
			},
		})
	}

	if len(problems) == 0 {
		return nil, warnings, nil
	}

	sort.Slice(problems, func(i, j int) bool {
		pi := problems[i].Position
		pj := problems[j].Position

		if pi.Filename != pj.Filename {
			return pi.Filename < pj.Filename
		}
		if pi.Line != pj.Line {
			return pi.Line < pj.Line
		}
		if pi.Column != pj.Column {
			return pi.Column < pj.Column
		}

		return problems[i].Message < problems[j].Message
	})

	var out []problem
	out = append(out, problems[0])
	for i, p := range problems[1:] {
		// We may encounter duplicate problems because one file
		// can be part of many packages.
		if !problems[i].equal(p) {
			out = append(out, p)
		}
	}
	return out, warnings, nil
}

func filterAnalyzerNames(analyzers []string, checks []string) map[string]bool {
	allowedChecks := map[string]bool{}

	for _, check := range checks {
		b := true
		if len(check) > 1 && check[0] == '-' {
			b = false
			check = check[1:]
		}
		if check == "*" || check == "all" {
			// Match all
			for _, c := range analyzers {
				allowedChecks[c] = b
			}
		} else if strings.HasSuffix(check, "*") {
			// Glob
			prefix := check[:len(check)-1]
			isCat := strings.IndexFunc(prefix, func(r rune) bool { return unicode.IsNumber(r) }) == -1

			for _, a := range analyzers {
				idx := strings.IndexFunc(a, func(r rune) bool { return unicode.IsNumber(r) })
				if isCat {
					// Glob is S*, which should match S1000 but not SA1000
					cat := a[:idx]
					if prefix == cat {
						allowedChecks[a] = b
					}
				} else {
					// Glob is S1*
					if strings.HasPrefix(a, prefix) {
						allowedChecks[a] = b
					}
				}
			}
		} else {
			// Literal check name
			allowedChecks[check] = b
		}
	}
	return allowedChecks
}

var posRe = regexp.MustCompile(`^(.+?):(\d+)(?::(\d+)?)?`)

func parsePos(pos string) (token.Position, int, error) {
	if pos == "-" || pos == "" {
		return token.Position{}, 0, nil
	}
	parts := posRe.FindStringSubmatch(pos)
	if parts == nil {
		return token.Position{}, 0, fmt.Errorf("internal error: malformed position %q", pos)
	}
	file := parts[1]
	line, _ := strconv.Atoi(parts[2])
	col, _ := strconv.Atoi(parts[3])
	return token.Position{
		Filename: file,
		Line:     line,
		Column:   col,
	}, len(parts[0]), nil
}

func usage(name string, flags *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", name)
		fmt.Fprintf(os.Stderr, "\t%s [flags] # runs on package in current directory\n", name)
		fmt.Fprintf(os.Stderr, "\t%s [flags] packages\n", name)
		fmt.Fprintf(os.Stderr, "\t%s [flags] directory\n", name)
		fmt.Fprintf(os.Stderr, "\t%s [flags] files... # must be a single package\n", name)
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flags.PrintDefaults()
	}
}

type list []string

func (list *list) String() string {
	return `"` + strings.Join(*list, ",") + `"`
}

func (list *list) Set(s string) error {
	if s == "" {
		*list = nil
		return nil
	}

	*list = strings.Split(s, ",")
	return nil
}

func FlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = usage(name, flags)
	flags.String("tags", "", "List of `build tags`")
	flags.Bool("tests", true, "Include tests")
	flags.Bool("version", false, "Print version and exit")
	flags.Bool("show-ignored", false, "Don't filter ignored problems")
	flags.String("f", "text", "Output `format` (valid choices are 'stylish', 'text' and 'json')")
	flags.String("explain", "", "Print description of `check`")

	flags.String("debug.cpuprofile", "", "Write CPU profile to `file`")
	flags.String("debug.memprofile", "", "Write memory profile to `file`")
	flags.Bool("debug.version", false, "Print detailed version information about this program")
	flags.Bool("debug.no-compile-errors", false, "Don't print compile errors")
	flags.String("debug.measure-analyzers", "", "Write analysis measurements to `file`. `file` will be opened for appending if it already exists.")
	flags.String("debug.trace", "", "Write trace to `file`")

	checks := list{"inherit"}
	fail := list{"all"}
	flags.Var(&checks, "checks", "Comma-separated list of `checks` to enable.")
	flags.Var(&fail, "fail", "Comma-separated list of `checks` that can cause a non-zero exit status.")

	tags := build.Default.ReleaseTags
	v := tags[len(tags)-1][2:]
	version := new(lint.VersionFlag)
	if err := version.Set(v); err != nil {
		panic(fmt.Sprintf("internal error: %s", err))
	}

	flags.Var(version, "go", "Target Go `version` in the format '1.x'")
	return flags
}

func findCheck(cs []*analysis.Analyzer, check string) (*analysis.Analyzer, bool) {
	for _, c := range cs {
		if c.Name == check {
			return c, true
		}
	}
	return nil, false
}

func ProcessFlagSet(cs []*analysis.Analyzer, fs *flag.FlagSet) {
	tags := fs.Lookup("tags").Value.(flag.Getter).Get().(string)
	tests := fs.Lookup("tests").Value.(flag.Getter).Get().(bool)
	goVersion := fs.Lookup("go").Value.(flag.Getter).Get().(int)
	theFormatter := fs.Lookup("f").Value.(flag.Getter).Get().(string)
	printVersion := fs.Lookup("version").Value.(flag.Getter).Get().(bool)
	showIgnored := fs.Lookup("show-ignored").Value.(flag.Getter).Get().(bool)
	explain := fs.Lookup("explain").Value.(flag.Getter).Get().(string)

	cpuProfile := fs.Lookup("debug.cpuprofile").Value.(flag.Getter).Get().(string)
	memProfile := fs.Lookup("debug.memprofile").Value.(flag.Getter).Get().(string)
	debugVersion := fs.Lookup("debug.version").Value.(flag.Getter).Get().(bool)
	debugNoCompile := fs.Lookup("debug.no-compile-errors").Value.(flag.Getter).Get().(bool)
	traceOut := fs.Lookup("debug.trace").Value.(flag.Getter).Get().(string)

	var measureAnalyzers func(analysis *analysis.Analyzer, pkg *loader.PackageSpec, d time.Duration)
	if path := fs.Lookup("debug.measure-analyzers").Value.(flag.Getter).Get().(string); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}

		mu := &sync.Mutex{}
		measureAnalyzers = func(analysis *analysis.Analyzer, pkg *loader.PackageSpec, d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			// FIXME(dh): print pkg.ID
			if _, err := fmt.Fprintf(f, "%s\t%s\t%d\n", analysis.Name, pkg, d.Nanoseconds()); err != nil {
				log.Println("error writing analysis measurements:", err)
			}
		}
	}

	cfg := config.Config{}
	cfg.Checks = *fs.Lookup("checks").Value.(*list)

	exit := func(code int) {
		if cpuProfile != "" {
			pprof.StopCPUProfile()
		}
		if memProfile != "" {
			f, err := os.Create(memProfile)
			if err != nil {
				panic(err)
			}
			runtime.GC()
			pprof.WriteHeapProfile(f)
		}
		if traceOut != "" {
			trace.Stop()
		}
		os.Exit(code)
	}
	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}
	if traceOut != "" {
		f, err := os.Create(traceOut)
		if err != nil {
			log.Fatal(err)
		}
		trace.Start(f)
	}

	if debugVersion {
		version.Verbose()
		exit(0)
	}

	if printVersion {
		version.Print()
		exit(0)
	}

	// Validate that the tags argument is well-formed. go/packages
	// doesn't detect malformed build flags and returns unhelpful
	// errors.
	tf := buildutil.TagsFlag{}
	if err := tf.Set(tags); err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("invalid value %q for flag -tags: %s", tags, err))
		exit(1)
	}

	if explain != "" {
		var haystack []*analysis.Analyzer
		haystack = append(haystack, cs...)
		check, ok := findCheck(haystack, explain)
		if !ok {
			fmt.Fprintln(os.Stderr, "Couldn't find check", explain)
			exit(1)
		}
		if check.Doc == "" {
			fmt.Fprintln(os.Stderr, explain, "has no documentation")
			exit(1)
		}
		fmt.Println(check.Doc)
		exit(0)
	}

	var f formatter
	switch theFormatter {
	case "text":
		f = textFormatter{W: os.Stdout}
	case "stylish":
		f = &stylishFormatter{W: os.Stdout}
	case "json":
		f = jsonFormatter{W: os.Stdout}
	case "null":
		f = nullFormatter{}
	default:
		fmt.Fprintf(os.Stderr, "unsupported output format %q\n", theFormatter)
		exit(2)
	}

	ps, warnings, err := doLint(cs, fs.Args(), &options{
		Tags:                     tags,
		LintTests:                tests,
		GoVersion:                goVersion,
		Config:                   cfg,
		PrintAnalyzerMeasurement: measureAnalyzers,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}

	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	var (
		numErrors   int
		numWarnings int
		numIgnored  int
	)

	fail := *fs.Lookup("fail").Value.(*list)
	analyzerNames := make([]string, len(cs))
	for i, a := range cs {
		analyzerNames[i] = a.Name
	}
	shouldExit := filterAnalyzerNames(analyzerNames, fail)
	shouldExit["staticcheck"] = true
	shouldExit["compile"] = true

	for _, p := range ps {
		if p.Category == "compile" && debugNoCompile {
			continue
		}
		if p.Severity == severityIgnored && !showIgnored {
			numIgnored++
			continue
		}
		if shouldExit[p.Category] {
			numErrors++
		} else {
			p.Severity = severityWarning
			numWarnings++
		}
		f.Format(p)
	}
	if f, ok := f.(statter); ok {
		f.Stats(len(ps), numErrors, numWarnings, numIgnored)
	}

	if numErrors > 0 {
		exit(1)
	}
	exit(0)
}

type options struct {
	Config config.Config

	Tags                     string
	LintTests                bool
	GoVersion                int
	PrintAnalyzerMeasurement func(analysis *analysis.Analyzer, pkg *loader.PackageSpec, d time.Duration)
}

func computeSalt() ([]byte, error) {
	if version.Version != "devel" {
		return []byte(version.Version), nil
	}
	p, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func doLint(cs []*analysis.Analyzer, paths []string, opt *options) ([]problem, []string, error) {
	salt, err := computeSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("could not compute salt for cache: %s", err)
	}
	cache.SetSalt(salt)

	if opt == nil {
		opt = &options{}
	}

	l, err := newLinter(opt.Config)
	if err != nil {
		return nil, nil, err
	}
	l.Checkers = cs
	l.SetGoVersion(opt.GoVersion)
	l.Runner.Stats.PrintAnalyzerMeasurement = opt.PrintAnalyzerMeasurement

	cfg := &packages.Config{}
	if opt.LintTests {
		cfg.Tests = true
	}
	if opt.Tags != "" {
		cfg.BuildFlags = append(cfg.BuildFlags, "-tags", opt.Tags)
	}

	printStats := func() {
		// Individual stats are read atomically, but overall there
		// is no synchronisation. For printing rough progress
		// information, this doesn't matter.
		switch l.Runner.Stats.State() {
		case runner.StateInitializing:
			fmt.Fprintln(os.Stderr, "Status: initializing")
		case runner.StateLoadPackageGraph:
			fmt.Fprintln(os.Stderr, "Status: loading package graph")
		case runner.StateBuildActionGraph:
			fmt.Fprintln(os.Stderr, "Status: building action graph")
		case runner.StateProcessing:
			fmt.Fprintf(os.Stderr, "Packages: %d/%d initial, %d/%d total; Workers: %d/%d\n",
				l.Runner.Stats.ProcessedInitialPackages(),
				l.Runner.Stats.InitialPackages(),
				l.Runner.Stats.ProcessedPackages(),
				l.Runner.Stats.TotalPackages(),
				l.Runner.ActiveWorkers(),
				l.Runner.TotalWorkers(),
			)
		case runner.StateFinalizing:
			fmt.Fprintln(os.Stderr, "Status: finalizing")
		}
	}
	if len(infoSignals) > 0 {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, infoSignals...)
		defer signal.Stop(ch)
		go func() {
			for range ch {
				printStats()
			}
		}()
	}
	return l.Lint(cfg, paths)
}
