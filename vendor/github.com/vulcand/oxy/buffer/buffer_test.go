package buffer

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/testutils"
	"github.com/vulcand/oxy/utils"

	. "gopkg.in/check.v1"
)

func TestBuffer(t *testing.T) { TestingT(t) }

type BFSuite struct{}

var _ = Suite(&BFSuite{})

func (s *BFSuite) TestSimple(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr)
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, body, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
	c.Assert(string(body), Equals, "hello")
}

func (s *BFSuite) TestChunkedEncodingSuccess(c *C) {
	var reqBody string
	var contentLength int64
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		c.Assert(err, IsNil)
		reqBody = string(body)
		contentLength = req.ContentLength
		w.Write([]byte("hello"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr)
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	conn, err := net.Dial("tcp", testutils.ParseURI(proxy.URL).Host)
	c.Assert(err, IsNil)
	fmt.Fprintf(conn, "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n5\r\ntest1\r\n5\r\ntest2\r\n0\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')

	c.Assert(reqBody, Equals, "testtest1test2")
	c.Assert(status, Equals, "HTTP/1.0 200 OK\r\n")
	c.Assert(contentLength, Equals, int64(len(reqBody)))
}

func (s *BFSuite) TestChunkedEncodingLimitReached(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr, MemRequestBodyBytes(4), MaxRequestBodyBytes(8))
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	conn, err := net.Dial("tcp", testutils.ParseURI(proxy.URL).Host)
	c.Assert(err, IsNil)
	fmt.Fprintf(conn, "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n5\r\ntest1\r\n5\r\ntest2\r\n0\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')

	c.Assert(status, Equals, "HTTP/1.0 413 Request Entity Too Large\r\n")
}

func (s *BFSuite) TestRequestLimitReached(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr, MaxRequestBodyBytes(4))
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL, testutils.Body("this request is too long"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusRequestEntityTooLarge)
}

func (s *BFSuite) TestResponseLimitReached(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello, this response is too large"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr, MaxResponseBodyBytes(4))
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusInternalServerError)
}

func (s *BFSuite) TestFileStreamingResponse(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello, this response is too large to fit in memory"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr, MemResponseBodyBytes(4))
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, body, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
	c.Assert(string(body), Equals, "hello, this response is too large to fit in memory")
}

func (s *BFSuite) TestCustomErrorHandler(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello, this response is too large"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	errHandler := utils.ErrorHandlerFunc(func(w http.ResponseWriter, req *http.Request, err error) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte(http.StatusText(http.StatusTeapot)))
	})
	st, err := New(rdr, MaxResponseBodyBytes(4), ErrorHandler(errHandler))
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusTeapot)
}

func (s *BFSuite) TestNotModified(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr)
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusNotModified)
}

func (s *BFSuite) TestNoBody(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr)
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

// Make sure that stream handler preserves TLS settings
func (s *BFSuite) TestPreservesTLS(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New()
	c.Assert(err, IsNil)

	var t *tls.ConnectionState
	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t = req.TLS
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	// stream handler will forward requests to redirect
	st, err := New(rdr)
	c.Assert(err, IsNil)

	proxy := httptest.NewUnstartedServer(st)
	proxy.StartTLS()
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)

	c.Assert(t, NotNil)
}
