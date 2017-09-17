package stream

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

	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
	"time"
)

func TestStream(t *testing.T) { TestingT(t) }

type STSuite struct{}

var _ = Suite(&STSuite{})

type noOpNextHttpHandler struct{}

func (n noOpNextHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

type noOpIoWriter struct{}

func (n noOpIoWriter) Write(bytes []byte) (int, error) {
	return len(bytes), nil
}

func (s *STSuite) TestSimple(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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

func (s *STSuite) TestChunkedEncodingSuccess(c *C) {
	var reqBody string
	var contentLength int64
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		c.Assert(err, IsNil)
		reqBody = string(body)
		contentLength = req.ContentLength

		w.WriteHeader(200)
		flusher, ok := w.(http.Flusher)
		if !ok {
			panic("expected http.ResponseWriter to be an http.Flusher")
		}
		fmt.Fprint(w, "Response")
		flusher.Flush()
		time.Sleep(time.Duration(500) * time.Millisecond)
		fmt.Fprint(w, "in")
		flusher.Flush()
		time.Sleep(time.Duration(500) * time.Millisecond)
		fmt.Fprint(w, "Chunks")
		flusher.Flush()
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n5\r\ntest1\r\n5\r\ntest2\r\n0\r\n\r\n")
	reader := bufio.NewReader(conn)

	status, err := reader.ReadString('\n')

	reader.ReadString('\n') //content type
	reader.ReadString('\n') //Date
	transferEncoding, _ := reader.ReadString('\n')

	c.Assert(transferEncoding, Equals, "Transfer-Encoding: chunked\r\n")
	c.Assert(contentLength, Equals, int64(-1))
	c.Assert(reqBody, Equals, "testtest1test2")
	c.Assert(status, Equals, "HTTP/1.1 200 OK\r\n")
}

func (s *STSuite) TestRequestLimitReached(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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

	re, _, err := testutils.Get(proxy.URL, testutils.Body("this request is too long"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *STSuite) TestResponseLimitReached(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello, this response is too large"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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

func (s *STSuite) TestFileStreamingResponse(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello, this response is too large to fit in memory"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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
	c.Assert(string(body), Equals, "hello, this response is too large to fit in memory")
}

func (s *STSuite) TestCustomErrorHandler(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello, this response is too large"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
	c.Assert(err, IsNil)

	// this is our redirect to server
	rdr := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL = testutils.ParseURI(srv.URL)
		fwd.ServeHTTP(w, req)
	})

	st, err := New(rdr)
	c.Assert(err, IsNil)

	proxy := httptest.NewServer(st)
	defer proxy.Close()

	re, _, err := testutils.Get(proxy.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *STSuite) TestNotModified(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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

func (s *STSuite) TestNoBody(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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
func (s *STSuite) TestPreservesTLS(c *C) {
	srv := testutils.NewHandler(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	defer srv.Close()

	// forwarder will proxy the request to whatever destination
	fwd, err := forward.New(forward.Stream(true))
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

func BenchmarkLoggingDebugLevel(b *testing.B) {
	streamer, _ := New(noOpNextHttpHandler{})

	log.SetLevel(log.DebugLevel)
	log.SetOutput(&noOpIoWriter{}) //Make sure we don't emit a bunch of stuff on screen

	for i := 0; i < b.N; i++ {
		heavyServeHttpLoad(streamer)
	}
}

func BenchmarkLoggingInfoLevel(b *testing.B) {
	streamer, _ := New(noOpNextHttpHandler{})

	log.SetLevel(log.InfoLevel)
	log.SetOutput(&noOpIoWriter{}) //Make sure we don't emit a bunch of stuff on screen

	for i := 0; i < b.N; i++ {
		heavyServeHttpLoad(streamer)
	}
}

func heavyServeHttpLoad(handler http.Handler) {
	w := httptest.NewRecorder()
	r := &http.Request{}
	handler.ServeHTTP(w, r)
}
