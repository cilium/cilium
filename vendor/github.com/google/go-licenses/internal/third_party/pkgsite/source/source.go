// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package source constructs public URLs that link to the source files in a module. It
// can be used to build references to Go source code, or to any other files in a
// module.
//
// Of course, the module zip file contains all the files in the module. This
// package attempts to find the origin of the zip file, in a repository that is
// publicly readable, and constructs links to that repo. While a module zip file
// could in theory come from anywhere, including a non-public location, this
// package recognizes standard module path patterns and construct repository
// URLs from them, like the go command does.
package source

//
// Much of this code was adapted from
// https://go.googlesource.com/gddo/+/refs/heads/master/gosrc
// and
// https://go.googlesource.com/go/+/refs/heads/master/src/cmd/go/internal/get

import (
	"context"
	"fmt"
	"log" // We cannot use glog instead, because its "v" flag conflicts with other libraries we use.
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-licenses/internal/third_party/pkgsite/derrors"
	"github.com/google/go-licenses/internal/third_party/pkgsite/stdlib"
	"github.com/google/go-licenses/internal/third_party/pkgsite/version"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/trace"
	"golang.org/x/net/context/ctxhttp"
)

// Info holds source information about a module, used to generate URLs referring
// to directories, files and lines.
type Info struct {
	repoURL   string       // URL of repo containing module; exported for DB schema compatibility
	moduleDir string       // directory of module relative to repo root
	commit    string       // tag or ID of commit corresponding to version
	templates urlTemplates // for building URLs
}

// FileURL returns a URL for a file whose pathname is relative to the module's home directory.
func (i *Info) FileURL(pathname string) string {
	if i == nil {
		return ""
	}
	dir, base := path.Split(pathname)
	return expand(i.templates.File, map[string]string{
		"repo":       i.repoURL,
		"importPath": path.Join(strings.TrimPrefix(i.repoURL, "https://"), dir),
		"commit":     i.commit,
		"dir":        dir,
		"file":       path.Join(i.moduleDir, pathname),
		"base":       base,
	})
}

type Client struct {
	// client used for HTTP requests. It is mutable for testing purposes.
	// If nil, then moduleInfoDynamic will return nil, nil; also for testing.
	httpClient *http.Client
}

// New constructs a *Client using the provided timeout.
func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: &ochttp.Transport{},
			Timeout:   timeout,
		},
	}
}

// NewClientForTesting returns a Client suitable for testing. It returns the
// same results as an ordinary client for statically recognizable paths, but
// always returns a nil *Info for dynamic paths (those requiring HTTP requests).
func NewClientForTesting() *Client {
	return &Client{}
}

// doURL makes an HTTP request using the given url and method. It returns an
// error if the request returns an error. If only200 is true, it also returns an
// error if any status code other than 200 is returned.
func (c *Client) doURL(ctx context.Context, method, url string, only200 bool) (_ *http.Response, err error) {
	defer derrors.Wrap(&err, "doURL(ctx, client, %q, %q)", method, url)

	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("c.httpClient cannot be nil")
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := ctxhttp.Do(ctx, c.httpClient, req)
	if err != nil {
		return nil, err
	}
	if only200 && resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return resp, nil
}

// ModuleInfo determines the repository corresponding to the module path. It
// returns a URL to that repo, as well as the directory of the module relative
// to the repo root.
//
// ModuleInfo may fetch from arbitrary URLs, so it can be slow.
func ModuleInfo(ctx context.Context, client *Client, modulePath, v string) (info *Info, err error) {
	defer derrors.Wrap(&err, "source.ModuleInfo(ctx, %q, %q)", modulePath, v)
	ctx, span := trace.StartSpan(ctx, "source.ModuleInfo")
	defer span.End()

	// The example.com domain can never be real; it is reserved for testing
	// (https://en.wikipedia.org/wiki/Example.com). Treat it as if it used
	// GitHub templates.
	if strings.HasPrefix(modulePath, "example.com/") {
		return NewGitHubInfo("https://"+modulePath, "", v), nil
	}

	if modulePath == stdlib.ModulePath {
		return newStdlibInfo(v)
	}

	repo, relativeModulePath, templates, transformCommit, err := matchStatic(modulePath)
	if err != nil {
		info, err = moduleInfoDynamic(ctx, client, modulePath, v)
		if err != nil {
			return nil, err
		}
	} else {
		commit, isHash := commitFromVersion(v, relativeModulePath)
		if transformCommit != nil {
			commit = transformCommit(commit, isHash)
		}
		info = &Info{
			repoURL:   trimVCSSuffix("https://" + repo),
			moduleDir: relativeModulePath,
			commit:    commit,
			templates: templates,
		}
	}
	if info != nil {
		adjustVersionedModuleDirectory(ctx, client, info)
	}
	if strings.HasPrefix(modulePath, "golang.org/") {
		adjustGoRepoInfo(info, modulePath, version.IsPseudo(v))
	}
	return info, nil
	// TODO(golang/go#39627): support launchpad.net, including the special case
	// in cmd/go/internal/get/vcs.go.
}

func newStdlibInfo(version string) (_ *Info, err error) {
	defer derrors.Wrap(&err, "newStdlibInfo(%q)", version)

	commit, err := stdlib.TagForVersion(version)
	if err != nil {
		return nil, err
	}

	templates := csopensourceTemplates
	templates.Raw = "https://github.com/golang/go/raw/{commit}/{file}"
	return &Info{
		repoURL:   stdlib.GoSourceRepoURL,
		moduleDir: stdlib.Directory(version),
		commit:    commit,
		templates: templates,
	}, nil
}

// csNonXRepos is a set of repos hosted at https://cs.opensource.google/go,
// that are not an x/repo.
var csNonXRepos = map[string]bool{
	"dl":        true,
	"proposal":  true,
	"vscode-go": true,
}

// csXRepos is the set of repos hosted at https://cs.opensource.google/go,
// that have a x/ prefix.
//
// x/scratch is not included.
var csXRepos = map[string]bool{
	"x/arch":       true,
	"x/benchmarks": true,
	"x/blog":       true,
	"x/build":      true,
	"x/crypto":     true,
	"x/debug":      true,
	"x/example":    true,
	"x/exp":        true,
	"x/image":      true,
	"x/mobile":     true,
	"x/mod":        true,
	"x/net":        true,
	"x/oauth2":     true,
	"x/perf":       true,
	"x/pkgsite":    true,
	"x/playground": true,
	"x/review":     true,
	"x/sync":       true,
	"x/sys":        true,
	"x/talks":      true,
	"x/term":       true,
	"x/text":       true,
	"x/time":       true,
	"x/tools":      true,
	"x/tour":       true,
	"x/vgo":        true,
	"x/website":    true,
	"x/xerrors":    true,
}

func adjustGoRepoInfo(info *Info, modulePath string, isHash bool) {
	suffix := strings.TrimPrefix(modulePath, "golang.org/")

	// Validate that this is a repo that exists on
	// https://cs.opensource.google/go. Otherwise, default to the existing
	// info.
	parts := strings.Split(suffix, "/")
	if len(parts) >= 2 {
		suffix = parts[0] + "/" + parts[1]
	}
	if strings.HasPrefix(suffix, "x/") {
		if !csXRepos[suffix] {
			return
		}
	} else if !csNonXRepos[suffix] {
		return
	}

	// rawURL needs to be set before info.templates is changed.
	rawURL := fmt.Sprintf(
		"https://github.com/golang/%s/raw/{commit}/{file}", strings.TrimPrefix(suffix, "x/"))

	info.repoURL = fmt.Sprintf("https://cs.opensource.google/go/%s", suffix)
	info.templates = csopensourceTemplates
	info.templates.Raw = rawURL

	if isHash {
		// When we have a pseudoversion, info.commit will be an actual commit
		// instead of a tag.
		//
		// https://cs.opensource.google/go/* has short commits hardcoded to 8
		// chars. Commits shorter or longer will not work, unless it is the full
		// commit hash.
		info.commit = info.commit[0:8]
	}
}

// matchStatic matches the given module or repo path against a list of known
// patterns. It returns the repo name, the module path relative to the repo
// root, and URL templates if there is a match.
//
// The relative module path may not be correct in all cases: it is wrong if it
// ends in a version that is not part of the repo directory structure, because
// the repo follows the "major branch" convention for versions 2 and above.
// E.g. this function could return "foo/v2", but the module files live under "foo"; the
// "/v2" is part of the module path (and the import paths of its packages) but
// is not a subdirectory. This mistake is corrected in adjustVersionedModuleDirectory,
// once we have all the information we need to fix it.
//
// repo + "/" + relativeModulePath is often, but not always, equal to
// moduleOrRepoPath. It is not when the argument is a module path that uses the
// go command's general syntax, which ends in a ".vcs" (e.g. ".git", ".hg") that
// is neither part of the repo nor the suffix. For example, if the argument is
//
//	github.com/a/b/c
//
// then repo="github.com/a/b" and relativeModulePath="c"; together they make up the module path.
// But if the argument is
//
//	example.com/a/b.git/c
//
// then repo="example.com/a/b" and relativeModulePath="c"; the ".git" is omitted, since it is neither
// part of the repo nor part of the relative path to the module within the repo.
func matchStatic(moduleOrRepoPath string) (repo, relativeModulePath string, _ urlTemplates, transformCommit transformCommitFunc, _ error) {
	for _, pat := range patterns {
		matches := pat.re.FindStringSubmatch(moduleOrRepoPath)
		if matches == nil {
			continue
		}
		var repo string
		for i, n := range pat.re.SubexpNames() {
			if n == "repo" {
				repo = matches[i]
				break
			}
		}
		// Special case: git.apache.org has a go-import tag that points to
		// github.com/apache, but it's not quite right (the repo prefix is
		// missing a ".git"), so handle it here.
		const apacheDomain = "git.apache.org/"
		if strings.HasPrefix(repo, apacheDomain) {
			repo = strings.Replace(repo, apacheDomain, "github.com/apache/", 1)
		}
		// Special case: module paths are blitiri.com.ar/go/..., but repos are blitiri.com.ar/git/r/...
		if strings.HasPrefix(repo, "blitiri.com.ar/") {
			repo = strings.Replace(repo, "/go/", "/git/r/", 1)
		}
		relativeModulePath = strings.TrimPrefix(moduleOrRepoPath, matches[0])
		relativeModulePath = strings.TrimPrefix(relativeModulePath, "/")
		return repo, relativeModulePath, pat.templates, pat.transformCommit, nil
	}
	return "", "", urlTemplates{}, nil, derrors.NotFound
}

// moduleInfoDynamic uses the go-import and go-source meta tags to construct an Info.
func moduleInfoDynamic(ctx context.Context, client *Client, modulePath, version string) (_ *Info, err error) {
	defer derrors.Wrap(&err, "moduleInfoDynamic(ctx, client, %q, %q)", modulePath, version)

	if client.httpClient == nil {
		return nil, nil // for testing
	}

	sourceMeta, err := fetchMeta(ctx, client, modulePath)
	if err != nil {
		return nil, err
	}
	// Don't check that the tag information at the repo root prefix is the same
	// as in the module path. It was done for us by the proxy and/or go command.
	// (This lets us merge information from the go-import and go-source tags.)

	// sourceMeta contains some information about where the module's source lives. But there
	// are some problems:
	// - We may only have a go-import tag, not a go-source tag, so we don't have URL templates for
	//   building URLs to files and directories.
	// - Even if we do have a go-source tag, its URL template format predates
	//   versioning, so the URL templates won't provide a way to specify a
	//   version or commit.
	//
	// We resolve these problems as follows:
	// 1. First look at the repo URL from the tag. If that matches a known hosting site, use the
	//    URL templates corresponding to that site and ignore whatever's in the tag.
	// 2. Then look at the URL templates to see if they match a known pattern, and use the templates
	//    from that pattern. For example, the meta tags for gopkg.in/yaml.v2 only mention github
	//    in the URL templates, like "https://github.com/go-yaml/yaml/tree/v2.2.3{/dir}". We can observe
	//    that that template begins with a known pattern--a GitHub repo, ignore the rest of it, and use the
	//    GitHub URL templates that we know.
	repoURL := sourceMeta.repoURL
	_, _, templates, transformCommit, _ := matchStatic(removeHTTPScheme(repoURL))
	// If err != nil, templates will be the zero value, so we can ignore it (same just below).
	if templates == (urlTemplates{}) {
		var repo string
		repo, _, templates, transformCommit, _ = matchStatic(removeHTTPScheme(sourceMeta.dirTemplate))
		if templates == (urlTemplates{}) {
			if err == nil {
				templates, transformCommit = matchLegacyTemplates(ctx, sourceMeta)
				repoURL = strings.TrimSuffix(repoURL, ".git")
			} else {
				log.Printf("no templates for repo URL %q from meta tag: err=%v", sourceMeta.repoURL, err)
			}
		} else {
			// Use the repo from the template, not the original one.
			repoURL = "https://" + repo
		}
	}
	dir := strings.TrimPrefix(strings.TrimPrefix(modulePath, sourceMeta.repoRootPrefix), "/")
	commit, isHash := commitFromVersion(version, dir)
	if transformCommit != nil {
		commit = transformCommit(commit, isHash)
	}
	return &Info{
		repoURL:   strings.TrimSuffix(repoURL, "/"),
		moduleDir: dir,
		commit:    commit,
		templates: templates,
	}, nil
}

// List of template regexps and their corresponding likely templates,
// used by matchLegacyTemplates below.
var legacyTemplateMatches = []struct {
	fileRegexp      *regexp.Regexp
	templates       urlTemplates
	transformCommit transformCommitFunc
}{
	{
		regexp.MustCompile(`/src/branch/\w+\{/dir\}/\{file\}#L\{line\}$`),
		giteaURLTemplates, giteaTransformCommit,
	},
	{
		regexp.MustCompile(`/src/\w+\{/dir\}/\{file\}#L\{line\}$`),
		giteaURLTemplates, nil,
	},
	{
		regexp.MustCompile(`/-/blob/\w+\{/dir\}/\{file\}#L\{line\}$`),
		gitlabURLTemplates, nil,
	},
	{
		regexp.MustCompile(`/tree\{/dir\}/\{file\}#n\{line\}$`),
		fdioURLTemplates, fdioTransformCommit,
	},
}

// matchLegacyTemplates matches the templates from the go-source meta tag
// against some known patterns to guess the version-aware URL templates. If it
// can't find a match, it falls back using the go-source templates with some
// small replacements. These will not be version-aware but will still serve
// source at a fixed commit, which is better than nothing.
func matchLegacyTemplates(ctx context.Context, sm *sourceMeta) (_ urlTemplates, transformCommit transformCommitFunc) {
	if sm.fileTemplate == "" {
		return urlTemplates{}, nil
	}
	for _, ltm := range legacyTemplateMatches {
		if ltm.fileRegexp.MatchString(sm.fileTemplate) {
			return ltm.templates, ltm.transformCommit
		}
	}
	log.Printf("matchLegacyTemplates: no matches for repo URL %q; replacing", sm.repoURL)
	rep := strings.NewReplacer(
		"{/dir}/{file}", "/{file}",
		"{dir}/{file}", "{file}",
		"{/dir}", "/{dir}")
	line := rep.Replace(sm.fileTemplate)
	file := line
	if i := strings.LastIndexByte(line, '#'); i > 0 {
		file = line[:i]
	}
	return urlTemplates{
		Repo:      sm.repoURL,
		Directory: rep.Replace(sm.dirTemplate),
		File:      file,
		Line:      line,
	}, nil
}

// adjustVersionedModuleDirectory changes info.moduleDir if necessary to
// correctly reflect the repo structure. info.moduleDir will be wrong if it has
// a suffix "/vN" for N > 1, and the repo uses the "major branch" convention,
// where modules at version 2 and higher live on branches rather than
// subdirectories. See https://research.swtch.com/vgo-module for a discussion of
// the "major branch" vs. "major subdirectory" conventions for organizing a
// repo.
func adjustVersionedModuleDirectory(ctx context.Context, client *Client, info *Info) {
	dirWithoutVersion := removeVersionSuffix(info.moduleDir)
	if info.moduleDir == dirWithoutVersion {
		return
	}
	// moduleDir does have a "/vN" for N > 1. To see if that is the actual directory,
	// fetch the go.mod file from it.
	res, err := client.doURL(ctx, "HEAD", info.FileURL("go.mod"), true)
	// On any failure, assume that the right directory is the one without the version.
	if err != nil {
		info.moduleDir = dirWithoutVersion
	} else {
		res.Body.Close()
	}
}

// removeHTTPScheme removes an initial "http://" or "https://" from url.
// The result can be used to match against our static patterns.
// If the URL uses a different scheme, it won't be removed and it won't
// match any patterns, as intended.
func removeHTTPScheme(url string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(url, prefix) {
			return url[len(prefix):]
		}
	}
	return url
}

// removeVersionSuffix returns s with "/vN" removed if N is an integer > 1.
// Otherwise it returns s.
func removeVersionSuffix(s string) string {
	dir, base := path.Split(s)
	if !strings.HasPrefix(base, "v") {
		return s
	}
	if n, err := strconv.Atoi(base[1:]); err != nil || n < 2 {
		return s
	}
	return strings.TrimSuffix(dir, "/")
}

type transformCommitFunc func(commit string, isHash bool) string

// Patterns for determining repo and URL templates from module paths or repo
// URLs. Each regexp must match a prefix of the target string, and must have a
// group named "repo".
var patterns = []struct {
	pattern   string // uncompiled regexp
	templates urlTemplates
	re        *regexp.Regexp
	// transformCommit may alter the commit before substitution
	transformCommit transformCommitFunc
}{
	{
		pattern:   `^(?P<repo>github\.com/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)`,
		templates: githubURLTemplates,
	},
	{
		// Assume that any site beginning with "github." works like github.com.
		pattern:   `^(?P<repo>github\.[a-z0-9A-Z.-]+/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates: githubURLTemplates,
	},
	{
		pattern:   `^(?P<repo>bitbucket\.org/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)`,
		templates: bitbucketURLTemplates,
	},
	{
		// Gitlab repos can have multiple path components.
		pattern:   `^(?P<repo>gitlab\.com/[^.]+)(\.git|$)`,
		templates: gitlabURLTemplates,
	},
	{
		// Assume that any site beginning with "gitlab." works like gitlab.com.
		pattern:   `^(?P<repo>gitlab\.[a-z0-9A-Z.-]+/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates: gitlabURLTemplates,
	},
	{
		pattern:   `^(?P<repo>gitee\.com/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates: githubURLTemplates,
	},
	{
		pattern: `^(?P<repo>git\.sr\.ht/~[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)`,
		templates: urlTemplates{
			Directory: "{repo}/tree/{commit}/{dir}",
			File:      "{repo}/tree/{commit}/{file}",
			Line:      "{repo}/tree/{commit}/{file}#L{line}",
			Raw:       "{repo}/blob/{commit}/{file}",
		},
	},
	{
		pattern:         `^(?P<repo>git\.fd\.io/[a-z0-9A-Z_.\-]+)`,
		templates:       fdioURLTemplates,
		transformCommit: fdioTransformCommit,
	},
	{
		pattern:   `^(?P<repo>git\.pirl\.io/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)`,
		templates: gitlabURLTemplates,
	},
	{
		pattern:         `^(?P<repo>gitea\.com/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates:       giteaURLTemplates,
		transformCommit: giteaTransformCommit,
	},
	{
		// Assume that any site beginning with "gitea." works like gitea.com.
		pattern:         `^(?P<repo>gitea\.[a-z0-9A-Z.-]+/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates:       giteaURLTemplates,
		transformCommit: giteaTransformCommit,
	},
	{
		pattern:         `^(?P<repo>go\.isomorphicgo\.org/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates:       giteaURLTemplates,
		transformCommit: giteaTransformCommit,
	},
	{
		pattern:         `^(?P<repo>git\.openprivacy\.ca/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates:       giteaURLTemplates,
		transformCommit: giteaTransformCommit,
	},
	{
		pattern:         `^(?P<repo>codeberg\.org/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		templates:       giteaURLTemplates,
		transformCommit: giteaTransformCommit,
	},
	{
		pattern: `^(?P<repo>gogs\.[a-z0-9A-Z.-]+/[a-z0-9A-Z_.\-]+/[a-z0-9A-Z_.\-]+)(\.git|$)`,
		// Gogs uses the same basic structure as Gitea, but omits the type of
		// commit ("tag" or "commit"), so we don't need a transformCommit
		// function. Gogs does not support short hashes, but we create those
		// URLs anyway. See gogs/gogs#6242.
		templates: giteaURLTemplates,
	},
	{
		pattern: `^(?P<repo>dmitri\.shuralyov\.com\/.+)$`,
		templates: urlTemplates{
			Repo:      "{repo}/...",
			Directory: "https://gotools.org/{importPath}?rev={commit}",
			File:      "https://gotools.org/{importPath}?rev={commit}#{base}",
			Line:      "https://gotools.org/{importPath}?rev={commit}#{base}-L{line}",
		},
	},
	{
		pattern: `^(?P<repo>blitiri\.com\.ar/go/.+)$`,
		templates: urlTemplates{
			Repo:      "{repo}",
			Directory: "{repo}/b/master/t/{dir}",
			File:      "{repo}/b/master/t/{dir}f={file}.html",
			Line:      "{repo}/b/master/t/{dir}f={file}.html#line-{line}",
		},
	},

	// Patterns that match the general go command pattern, where they must have
	// a ".git" repo suffix in an import path. If matching a repo URL from a meta tag,
	// there is no ".git".
	{
		pattern:   `^(?P<repo>[^.]+\.googlesource\.com/[^.]+)(\.git|$)`,
		templates: googlesourceURLTemplates,
	},
	{
		pattern:   `^(?P<repo>git\.apache\.org/[^.]+)(\.git|$)`,
		templates: githubURLTemplates,
	},
	// General syntax for the go command. We can extract the repo and directory, but
	// we don't know the URL templates.
	// Must be last in this list.
	{
		pattern:   `(?P<repo>([a-z0-9.\-]+\.)+[a-z0-9.\-]+(:[0-9]+)?(/~?[A-Za-z0-9_.\-]+)+?)\.(bzr|fossil|git|hg|svn)`,
		templates: urlTemplates{},
	},
}

func init() {
	for i := range patterns {
		re := regexp.MustCompile(patterns[i].pattern)
		// The pattern regexp must contain a group named "repo".
		found := false
		for _, n := range re.SubexpNames() {
			if n == "repo" {
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Sprintf("pattern %s missing <repo> group", patterns[i].pattern))
		}
		patterns[i].re = re
	}
}

// giteaTransformCommit transforms commits for the Gitea code hosting system.
func giteaTransformCommit(commit string, isHash bool) string {
	// Hashes use "commit", tags use "tag".
	// Short hashes are supported as of v1.14.0.
	if isHash {
		return "commit/" + commit
	}
	return "tag/" + commit
}

func fdioTransformCommit(commit string, isHash bool) string {
	// hashes use "?id=", tags use "?h="
	p := "h"
	if isHash {
		p = "id"
	}
	return fmt.Sprintf("%s=%s", p, commit)
}

// urlTemplates describes how to build URLs from bits of source information.
// The fields are exported for JSON encoding.
//
// The template variables are:
//
//   - {repo}       - Repository URL with "https://" prefix ("https://example.com/myrepo").
//   - {importPath} - Package import path ("example.com/myrepo/mypkg").
//   - {commit}     - Tag name or commit hash corresponding to version ("v0.1.0" or "1234567890ab").
//   - {dir}        - Path to directory of the package, relative to repo root ("mypkg").
//   - {file}       - Path to file containing the identifier, relative to repo root ("mypkg/file.go").
//   - {base}       - Base name of file containing the identifier, including file extension ("file.go").
//   - {line}       - Line number for the identifier ("41").
type urlTemplates struct {
	Repo      string `json:",omitempty"` // Optional URL template for the repository home page, with {repo}. If left empty, a default template "{repo}" is used.
	Directory string // URL template for a directory, with {repo}, {importPath}, {commit}, {dir}.
	File      string // URL template for a file, with {repo}, {importPath}, {commit}, {file}, {base}.
	Line      string // URL template for a line, with {repo}, {importPath}, {commit}, {file}, {base}, {line}.
	Raw       string // Optional URL template for the raw contents of a file, with {repo}, {commit}, {file}.
}

var (
	githubURLTemplates = urlTemplates{
		Directory: "{repo}/tree/{commit}/{dir}",
		File:      "{repo}/blob/{commit}/{file}",
		Line:      "{repo}/blob/{commit}/{file}#L{line}",
		Raw:       "{repo}/raw/{commit}/{file}",
	}

	bitbucketURLTemplates = urlTemplates{
		Directory: "{repo}/src/{commit}/{dir}",
		File:      "{repo}/src/{commit}/{file}",
		Line:      "{repo}/src/{commit}/{file}#lines-{line}",
		Raw:       "{repo}/raw/{commit}/{file}",
	}
	giteaURLTemplates = urlTemplates{
		Directory: "{repo}/src/{commit}/{dir}",
		File:      "{repo}/src/{commit}/{file}",
		Line:      "{repo}/src/{commit}/{file}#L{line}",
		Raw:       "{repo}/raw/{commit}/{file}",
	}
	googlesourceURLTemplates = urlTemplates{
		Directory: "{repo}/+/{commit}/{dir}",
		File:      "{repo}/+/{commit}/{file}",
		Line:      "{repo}/+/{commit}/{file}#{line}",
		// Gitiles has no support for serving raw content at this time.
	}
	gitlabURLTemplates = urlTemplates{
		Directory: "{repo}/-/tree/{commit}/{dir}",
		File:      "{repo}/-/blob/{commit}/{file}",
		Line:      "{repo}/-/blob/{commit}/{file}#L{line}",
		Raw:       "{repo}/-/raw/{commit}/{file}",
	}
	fdioURLTemplates = urlTemplates{
		Directory: "{repo}/tree/{dir}?{commit}",
		File:      "{repo}/tree/{file}?{commit}",
		Line:      "{repo}/tree/{file}?{commit}#n{line}",
		Raw:       "{repo}/plain/{file}?{commit}",
	}
	csopensourceTemplates = urlTemplates{
		Directory: "{repo}/+/{commit}:{dir}",
		File:      "{repo}/+/{commit}:{file}",
		Line:      "{repo}/+/{commit}:{file};l={line}",
		// Gitiles has no support for serving raw content at this time.
	}
)

// commitFromVersion returns a string that refers to a commit corresponding to version.
// It also reports whether the returned value is a commit hash.
// The string may be a tag, or it may be the hash or similar unique identifier of a commit.
// The second argument is the module path relative to the repo root.
func commitFromVersion(vers, relativeModulePath string) (commit string, isHash bool) {
	// Commit for the module: either a sha for pseudoversions, or a tag.
	v := strings.TrimSuffix(vers, "+incompatible")
	if version.IsPseudo(v) {
		// Use the commit hash at the end.
		return v[strings.LastIndex(v, "-")+1:], true
	} else {
		// The tags for a nested module begin with the relative module path of the module,
		// removing a "/vN" suffix if N > 1.
		prefix := removeVersionSuffix(relativeModulePath)
		if prefix != "" {
			return prefix + "/" + v, false
		}
		return v, false
	}
}

// trimVCSSuffix removes a VCS suffix from a repo URL in selected cases.
//
// The Go command allows a VCS suffix on a repo, like github.com/foo/bar.git. But
// some code hosting sites don't support all paths constructed from such URLs.
// For example, GitHub will redirect github.com/foo/bar.git to github.com/foo/bar,
// but will 404 on github.com/goo/bar.git/tree/master and any other URL with a
// non-empty path.
//
// To be conservative, we remove the suffix only in cases where we know it's
// wrong.
func trimVCSSuffix(repoURL string) string {
	if !strings.HasSuffix(repoURL, ".git") {
		return repoURL
	}
	if strings.HasPrefix(repoURL, "https://github.com/") || strings.HasPrefix(repoURL, "https://gitlab.com/") {
		return strings.TrimSuffix(repoURL, ".git")
	}
	return repoURL
}

// The following code copied from cmd/go/internal/get:

// expand rewrites s to replace {k} with match[k] for each key k in match.
func expand(s string, match map[string]string) string {
	// We want to replace each match exactly once, and the result of expansion
	// must not depend on the iteration order through the map.
	// A strings.Replacer has exactly the properties we're looking for.
	oldNew := make([]string, 0, 2*len(match))
	for k, v := range match {
		oldNew = append(oldNew, "{"+k+"}", v)
	}
	return strings.NewReplacer(oldNew...).Replace(s)
}

// NewGitHubInfo creates a source.Info with GitHub URL templates.
// It is for testing only.
func NewGitHubInfo(repoURL, moduleDir, commit string) *Info {
	return &Info{
		repoURL:   trimVCSSuffix(repoURL),
		moduleDir: moduleDir,
		commit:    commit,
		templates: githubURLTemplates,
	}
}
