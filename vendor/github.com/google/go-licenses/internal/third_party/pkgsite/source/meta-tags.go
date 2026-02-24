// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package source

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-licenses/internal/third_party/pkgsite/derrors"
)

// This code adapted from https://go.googlesource.com/gddo/+/refs/heads/master/gosrc/gosrc.go.

// sourceMeta represents the values in a go-source meta tag, or as a fallback,
// values from a go-import meta tag.
// The go-source spec is at https://github.com/golang/gddo/wiki/Source-Code-Links.
// The go-import spec is in "go help importpath".
type sourceMeta struct {
	repoRootPrefix string // import path prefix corresponding to repo root
	repoURL        string // URL of the repo root
	// The next two are only present in a go-source tag.
	dirTemplate  string // URL template for a directory
	fileTemplate string // URL template for a file and line
}

// fetchMeta retrieves go-import and go-source meta tag information, using the import path to construct
// a URL as described in "go help importpath".
//
// The importPath argument, as the name suggests, could be any package import
// path. But we only pass module paths.
//
// The discovery site only cares about linking to source, not fetching it (we
// already have it in the module zip file). So we merge the go-import and
// go-source meta tag information, preferring the latter.
func fetchMeta(ctx context.Context, client *Client, importPath string) (_ *sourceMeta, err error) {
	defer derrors.Wrap(&err, "fetchMeta(ctx, client, %q)", importPath)

	uri := importPath
	if !strings.Contains(uri, "/") {
		// Add slash for root of domain.
		uri = uri + "/"
	}
	uri = uri + "?go-get=1"

	resp, err := client.doURL(ctx, "GET", "https://"+uri, true)
	if err != nil {
		resp, err = client.doURL(ctx, "GET", "http://"+uri, false)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()
	return parseMeta(importPath, resp.Body)
}

func parseMeta(importPath string, r io.Reader) (sm *sourceMeta, err error) {
	errorMessage := "go-import and go-source meta tags not found"
	// gddo uses an xml parser, and this code is adapted from it.
	d := xml.NewDecoder(r)
	d.Strict = false
metaScan:
	for {
		t, tokenErr := d.Token()
		if tokenErr != nil {
			break metaScan
		}
		switch t := t.(type) {
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "head") {
				break metaScan
			}
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "body") {
				break metaScan
			}
			if !strings.EqualFold(t.Name.Local, "meta") {
				continue metaScan
			}
			nameAttr := attrValue(t.Attr, "name")
			if nameAttr != "go-import" && nameAttr != "go-source" {
				continue metaScan
			}
			fields := strings.Fields(attrValue(t.Attr, "content"))
			if len(fields) < 1 {
				continue metaScan
			}
			repoRootPrefix := fields[0]
			if !strings.HasPrefix(importPath, repoRootPrefix) ||
				!(len(importPath) == len(repoRootPrefix) || importPath[len(repoRootPrefix)] == '/') {
				// Ignore if root is not a prefix of the  path. This allows a
				// site to use a single error page for multiple repositories.
				continue metaScan
			}
			switch nameAttr {
			case "go-import":
				if len(fields) != 3 {
					errorMessage = "go-import meta tag content attribute does not have three fields"
					continue metaScan
				}
				if fields[1] == "mod" {
					// We can't make source links from a "mod" vcs type, so skip it.
					continue
				}
				if sm != nil {
					sm = nil
					errorMessage = "more than one go-import meta tag found"
					break metaScan
				}
				sm = &sourceMeta{
					repoRootPrefix: repoRootPrefix,
					repoURL:        fields[2],
				}
				// Keep going in the hope of finding a go-source tag.
			case "go-source":
				if len(fields) != 4 {
					errorMessage = "go-source meta tag content attribute does not have four fields"
					continue metaScan
				}
				if sm != nil && sm.repoRootPrefix != repoRootPrefix {
					errorMessage = fmt.Sprintf("import path prefixes %q for go-import and %q for go-source disagree", sm.repoRootPrefix, repoRootPrefix)
					sm = nil
					break metaScan
				}
				// If go-source repo is "_", then default to the go-import repo.
				repoURL := fields[1]
				if repoURL == "_" {
					if sm == nil {
						errorMessage = `go-source repo is "_", but no previous go-import tag`
						break metaScan
					}
					repoURL = sm.repoURL
				}
				sm = &sourceMeta{
					repoRootPrefix: repoRootPrefix,
					repoURL:        repoURL,
					dirTemplate:    fields[2],
					fileTemplate:   fields[3],
				}
				break metaScan
			}
		}
	}
	if sm == nil {
		return nil, fmt.Errorf("%s: %w", errorMessage, derrors.NotFound)
	}
	return sm, nil
}

func attrValue(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if strings.EqualFold(a.Name.Local, name) {
			return a.Value
		}
	}
	return ""
}
