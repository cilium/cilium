package utils

import (
	"net/http"
	"net/url"
	"testing"

	. "gopkg.in/check.v1"
)

func TestUtils(t *testing.T) { TestingT(t) }

type NetUtilsSuite struct{}

var _ = Suite(&NetUtilsSuite{})

// Make sure copy does it right, so the copied url
// is safe to alter without modifying the other
func (s *NetUtilsSuite) TestCopyUrl(c *C) {
	urlA := &url.URL{
		Scheme:   "http",
		Host:     "localhost:5000",
		Path:     "/upstream",
		Opaque:   "opaque",
		RawQuery: "a=1&b=2",
		Fragment: "#hello",
		User:     &url.Userinfo{},
	}
	urlB := CopyURL(urlA)
	c.Assert(urlB, DeepEquals, urlA)
	urlB.Scheme = "https"
	c.Assert(urlB, Not(DeepEquals), urlA)
}

// Make sure copy headers is not shallow and copies all headers
func (s *NetUtilsSuite) TestCopyHeaders(c *C) {
	source, destination := make(http.Header), make(http.Header)
	source.Add("a", "b")
	source.Add("c", "d")

	CopyHeaders(destination, source)

	c.Assert(destination.Get("a"), Equals, "b")
	c.Assert(destination.Get("c"), Equals, "d")

	// make sure that altering source does not affect the destination
	source.Del("a")
	c.Assert(source.Get("a"), Equals, "")
	c.Assert(destination.Get("a"), Equals, "b")
}

func (s *NetUtilsSuite) TestHasHeaders(c *C) {
	source := make(http.Header)
	source.Add("a", "b")
	source.Add("c", "d")
	c.Assert(HasHeaders([]string{"a", "f"}, source), Equals, true)
	c.Assert(HasHeaders([]string{"i", "j"}, source), Equals, false)
}

func (s *NetUtilsSuite) TestRemoveHeaders(c *C) {
	source := make(http.Header)
	source.Add("a", "b")
	source.Add("a", "m")
	source.Add("c", "d")
	RemoveHeaders(source, "a")
	c.Assert(source.Get("a"), Equals, "")
	c.Assert(source.Get("c"), Equals, "d")
}

func BenchmarkCopyHeaders(b *testing.B) {
	dstHeaders := make([]http.Header, 0, b.N)
	sourceHeaders := make([]http.Header, 0, b.N)
	for n := 0; n < b.N; n++ {
		// example from a reverse proxy merging headers
		d := http.Header{}
		d.Add("Request-Id", "1bd36bcc-a0d1-4fc7-aedc-20bbdefa27c5")
		dstHeaders = append(dstHeaders, d)

		s := http.Header{}
		s.Add("Content-Length", "374")
		s.Add("Context-Type", "text/html; charset=utf-8")
		s.Add("Etag", `"op14g6ae"`)
		s.Add("Last-Modified", "Wed, 26 Apr 2017 18:24:06 GMT")
		s.Add("Server", "Caddy")
		s.Add("Date", "Fri, 28 Apr 2017 15:54:01 GMT")
		s.Add("Accept-Ranges", "bytes")
		sourceHeaders = append(sourceHeaders, s)
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		CopyHeaders(dstHeaders[n], sourceHeaders[n])
	}
}
