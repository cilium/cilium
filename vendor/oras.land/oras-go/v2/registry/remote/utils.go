/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// defaultMaxMetadataBytes specifies the default limit on how many response
// bytes are allowed in the server's response to the metadata APIs.
// See also: Repository.MaxMetadataBytes
var defaultMaxMetadataBytes int64 = 4 * 1024 * 1024 // 4 MiB

// errNoLink is returned by parseLink() when no Link header is present.
var errNoLink = errors.New("no Link header in response")

// parseLink returns the URL of the response's "Link" header, if present.
func parseLink(resp *http.Response) (string, error) {
	link := resp.Header.Get("Link")
	if link == "" {
		return "", errNoLink
	}
	if link[0] != '<' {
		return "", fmt.Errorf("invalid next link %q: missing '<'", link)
	}
	if i := strings.IndexByte(link, '>'); i == -1 {
		return "", fmt.Errorf("invalid next link %q: missing '>'", link)
	} else {
		link = link[1:i]
	}

	linkURL, err := resp.Request.URL.Parse(link)
	if err != nil {
		return "", err
	}
	// The Link header value is controlled by the (potentially malicious)
	// registry. Restrict pagination to the same origin as the originating
	// request so that a registry cannot redirect pagination to an arbitrary
	// host and turn a listing call into a server-side request forgery.
	if !isSameOrigin(resp.Request.URL, linkURL) {
		return "", fmt.Errorf("invalid next link %q: not the same origin as %q", link, resp.Request.URL)
	}
	return linkURL.String(), nil
}

// isSameOrigin reports whether the two URLs share the same origin, that is the
// same scheme, host, and port (with the default port applied for http/https).
func isSameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	return canonicalHostPort(a) == canonicalHostPort(b)
}

// canonicalHostPort returns the lower-cased "host:port" of u, filling in the
// default port for the http and https schemes when none is present.
func canonicalHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// limitReader returns a Reader that reads from r but stops with EOF after n
// bytes. If n is less than or equal to zero, defaultMaxMetadataBytes is used.
func limitReader(r io.Reader, n int64) io.Reader {
	if n <= 0 {
		n = defaultMaxMetadataBytes
	}
	return io.LimitReader(r, n)
}

// limitSize returns ErrSizeExceedsLimit if the size of desc exceeds the limit n.
// If n is less than or equal to zero, defaultMaxMetadataBytes is used.
func limitSize(desc ocispec.Descriptor, n int64) error {
	if n <= 0 {
		n = defaultMaxMetadataBytes
	}
	if desc.Size > n {
		return fmt.Errorf(
			"content size %v exceeds MaxMetadataBytes %v: %w",
			desc.Size,
			n,
			errdef.ErrSizeExceedsLimit)
	}
	return nil
}

// decodeJSON safely reads the JSON content described by desc, and
// decodes it into v.
func decodeJSON(r io.Reader, desc ocispec.Descriptor, v any) error {
	jsonBytes, err := content.ReadAll(r, desc)
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonBytes, v)
}
