/*
package buffer provides http.Handler middleware that solves several problems when dealing with http requests:

Reads the entire request and response into buffer, optionally buffering it to disk for large requests.
Checks the limits for the requests and responses, rejecting in case if the limit was exceeded.
Changes request content-transfer-encoding from chunked and provides total size to the handlers.

Examples of a buffering middleware:

  // sample HTTP handler
  handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
    w.Write([]byte("hello"))
  })

  // Buffer will read the body in buffer before passing the request to the handler
  // calculate total size of the request and transform it from chunked encoding
  // before passing to the server
  buffer.New(handler)

  // This version will buffer up to 2MB in memory and will serialize any extra
  // to a temporary file, if the request size exceeds 10MB it will reject the request
  buffer.New(handler,
    buffer.MemRequestBodyBytes(2 * 1024 * 1024),
    buffer.MaxRequestBodyBytes(10 * 1024 * 1024))

  // Will do the same as above, but with responses
  buffer.New(handler,
    buffer.MemResponseBodyBytes(2 * 1024 * 1024),
    buffer.MaxResponseBodyBytes(10 * 1024 * 1024))

  // Buffer will replay the request if the handler returns error at least 3 times
  // before returning the response
  buffer.New(handler, buffer.Retry(`IsNetworkError() && Attempts() <= 2`))

*/
package buffer

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"bufio"
	log "github.com/sirupsen/logrus"
	"github.com/mailgun/multibuf"
	"github.com/vulcand/oxy/utils"
	"net"
	"reflect"
)

const (
	// Store up to 1MB in RAM
	DefaultMemBodyBytes = 1048576
	// No limit by default
	DefaultMaxBodyBytes = -1
	// Maximum retry attempts
	DefaultMaxRetryAttempts = 10
)

var errHandler utils.ErrorHandler = &SizeErrHandler{}

// Buffer is responsible for buffering requests and responses
// It buffers large reqeuests and responses to disk,
type Buffer struct {
	maxRequestBodyBytes int64
	memRequestBodyBytes int64

	maxResponseBodyBytes int64
	memResponseBodyBytes int64

	retryPredicate hpredicate

	next       http.Handler
	errHandler utils.ErrorHandler
}

// New returns a new buffer middleware. New() function supports optional functional arguments
func New(next http.Handler, setters ...optSetter) (*Buffer, error) {
	strm := &Buffer{
		next: next,

		maxRequestBodyBytes: DefaultMaxBodyBytes,
		memRequestBodyBytes: DefaultMemBodyBytes,

		maxResponseBodyBytes: DefaultMaxBodyBytes,
		memResponseBodyBytes: DefaultMemBodyBytes,
	}
	for _, s := range setters {
		if err := s(strm); err != nil {
			return nil, err
		}
	}
	if strm.errHandler == nil {
		strm.errHandler = errHandler
	}

	return strm, nil
}

type optSetter func(s *Buffer) error

// Retry provides a predicate that allows buffer middleware to replay the request
// if it matches certain condition, e.g. returns special error code. Available functions are:
//
// Attempts() - limits the amount of retry attempts
// ResponseCode() - returns http response code
// IsNetworkError() - tests if response code is related to networking error
//
// Example of the predicate:
//
// `Attempts() <= 2 && ResponseCode() == 502`
//
func Retry(predicate string) optSetter {
	return func(s *Buffer) error {
		p, err := parseExpression(predicate)
		if err != nil {
			return err
		}
		s.retryPredicate = p
		return nil
	}
}

// ErrorHandler sets error handler of the server
func ErrorHandler(h utils.ErrorHandler) optSetter {
	return func(s *Buffer) error {
		s.errHandler = h
		return nil
	}
}

// MaxRequestBodyBytes sets the maximum request body size in bytes
func MaxRequestBodyBytes(m int64) optSetter {
	return func(s *Buffer) error {
		if m < 0 {
			return fmt.Errorf("max bytes should be >= 0 got %d", m)
		}
		s.maxRequestBodyBytes = m
		return nil
	}
}

// MaxRequestBody bytes sets the maximum request body to be stored in memory
// buffer middleware will serialize the excess to disk.
func MemRequestBodyBytes(m int64) optSetter {
	return func(s *Buffer) error {
		if m < 0 {
			return fmt.Errorf("mem bytes should be >= 0 got %d", m)
		}
		s.memRequestBodyBytes = m
		return nil
	}
}

// MaxResponseBodyBytes sets the maximum request body size in bytes
func MaxResponseBodyBytes(m int64) optSetter {
	return func(s *Buffer) error {
		if m < 0 {
			return fmt.Errorf("max bytes should be >= 0 got %d", m)
		}
		s.maxResponseBodyBytes = m
		return nil
	}
}

// MemResponseBodyBytes sets the maximum request body to be stored in memory
// buffer middleware will serialize the excess to disk.
func MemResponseBodyBytes(m int64) optSetter {
	return func(s *Buffer) error {
		if m < 0 {
			return fmt.Errorf("mem bytes should be >= 0 got %d", m)
		}
		s.memResponseBodyBytes = m
		return nil
	}
}

// Wrap sets the next handler to be called by buffer handler.
func (s *Buffer) Wrap(next http.Handler) error {
	s.next = next
	return nil
}

func (s *Buffer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if log.GetLevel() >= log.DebugLevel {
		logEntry := log.WithField("Request", utils.DumpHttpRequest(req))
		logEntry.Debug("vulcand/oxy/buffer: begin ServeHttp on request")
		defer logEntry.Debug("vulcand/oxy/buffer: competed ServeHttp on request")
	}

	if err := s.checkLimit(req); err != nil {
		log.Errorf("vulcand/oxy/buffer: request body over limit, err: %v", err)
		s.errHandler.ServeHTTP(w, req, err)
		return
	}

	// Read the body while keeping limits in mind. This reader controls the maximum bytes
	// to read into memory and disk. This reader returns an error if the total request size exceeds the
	// prefefined MaxSizeBytes. This can occur if we got chunked request, in this case ContentLength would be set to -1
	// and the reader would be unbounded bufio in the http.Server
	body, err := multibuf.New(req.Body, multibuf.MaxBytes(s.maxRequestBodyBytes), multibuf.MemBytes(s.memRequestBodyBytes))
	if err != nil || body == nil {
		log.Errorf("vulcand/oxy/buffer: error when reading request body, err: %v", err)
		s.errHandler.ServeHTTP(w, req, err)
		return
	}

	// Set request body to buffered reader that can replay the read and execute Seek
	// Note that we don't change the original request body as it's handled by the http server
	// and we don'w want to mess with standard library
	defer body.Close()

	// We need to set ContentLength based on known request size. The incoming request may have been
	// set without content length or using chunked TransferEncoding
	totalSize, err := body.Size()
	if err != nil {
		log.Errorf("vulcand/oxy/buffer: failed to get request size, err: %v", err)
		s.errHandler.ServeHTTP(w, req, err)
		return
	}

	outreq := s.copyRequest(req, body, totalSize)

	attempt := 1
	for {
		// We create a special writer that will limit the response size, buffer it to disk if necessary
		writer, err := multibuf.NewWriterOnce(multibuf.MaxBytes(s.maxResponseBodyBytes), multibuf.MemBytes(s.memResponseBodyBytes))
		if err != nil {
			log.Errorf("vulcand/oxy/buffer: failed create response writer, err: %v", err)
			s.errHandler.ServeHTTP(w, req, err)
			return
		}

		// We are mimicking http.ResponseWriter to replace writer with our special writer
		b := &bufferWriter{
			header:         make(http.Header),
			buffer:         writer,
			responseWriter: w,
		}
		defer b.Close()

		s.next.ServeHTTP(b, outreq)
		if b.hijacked {
			log.Infof("vulcand/oxy/buffer: connection was hijacked downstream. Not taking any action in buffer.")
			return
		}

		var reader multibuf.MultiReader
		if b.expectBody(outreq) {
			rdr, err := writer.Reader()
			if err != nil {
				log.Errorf("vulcand/oxy/buffer: failed to read response, err: %v", err)
				s.errHandler.ServeHTTP(w, req, err)
				return
			}
			defer rdr.Close()
			reader = rdr
		}

		if (s.retryPredicate == nil || attempt > DefaultMaxRetryAttempts) ||
			!s.retryPredicate(&context{r: req, attempt: attempt, responseCode: b.code}) {
			utils.CopyHeaders(w.Header(), b.Header())
			w.WriteHeader(b.code)
			if reader != nil {
				io.Copy(w, reader)
			}
			return
		}

		attempt += 1
		if _, err := body.Seek(0, 0); err != nil {
			log.Errorf("vulcand/oxy/buffer: failed to rewind response body, err: %v", err)
			s.errHandler.ServeHTTP(w, req, err)
			return
		}
		outreq = s.copyRequest(req, body, totalSize)
		log.Infof("vulcand/oxy/buffer: retry Request(%v %v) attempt %v", req.Method, req.URL, attempt)
	}
}

func (s *Buffer) copyRequest(req *http.Request, body io.ReadCloser, bodySize int64) *http.Request {
	o := *req
	o.URL = utils.CopyURL(req.URL)
	o.Header = make(http.Header)
	utils.CopyHeaders(o.Header, req.Header)
	o.ContentLength = bodySize
	// remove TransferEncoding that could have been previously set because we have transformed the request from chunked encoding
	o.TransferEncoding = []string{}
	// http.Transport will close the request body on any error, we are controlling the close process ourselves, so we override the closer here
	o.Body = ioutil.NopCloser(body)
	return &o
}

func (s *Buffer) checkLimit(req *http.Request) error {
	if s.maxRequestBodyBytes <= 0 {
		return nil
	}
	if req.ContentLength > s.maxRequestBodyBytes {
		return &multibuf.MaxSizeReachedError{MaxSize: s.maxRequestBodyBytes}
	}
	return nil
}

type bufferWriter struct {
	header         http.Header
	code           int
	buffer         multibuf.WriterOnce
	responseWriter http.ResponseWriter
	hijacked       bool
}

// RFC2616 #4.4
func (b *bufferWriter) expectBody(r *http.Request) bool {
	if r.Method == "HEAD" {
		return false
	}
	if (b.code >= 100 && b.code < 200) || b.code == 204 || b.code == 304 {
		return false
	}
	if b.header.Get("Content-Length") == "" && b.header.Get("Transfer-Encoding") == "" {
		return false
	}
	if b.header.Get("Content-Length") == "0" {
		return false
	}
	return true
}

func (b *bufferWriter) Close() error {
	return b.buffer.Close()
}

func (b *bufferWriter) Header() http.Header {
	return b.header
}

func (b *bufferWriter) Write(buf []byte) (int, error) {
	return b.buffer.Write(buf)
}

// WriteHeader sets rw.Code.
func (b *bufferWriter) WriteHeader(code int) {
	b.code = code
}

//CloseNotifier interface - this allows downstream connections to be terminated when the client terminates.
func (b *bufferWriter) CloseNotify() <-chan bool {
	if cn, ok := b.responseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	log.Warningf("Upstream ResponseWriter of type %v does not implement http.CloseNotifier. Returning dummy channel.", reflect.TypeOf(b.responseWriter))
	return make(<-chan bool)
}

//This allows connections to be hijacked for websockets for instance.
func (b *bufferWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hi, ok := b.responseWriter.(http.Hijacker); ok {
		conn, rw, err := hi.Hijack()
		if err != nil {
			b.hijacked = true
		}
		return conn, rw, err
	}
	log.Warningf("Upstream ResponseWriter of type %v does not implement http.Hijacker. Returning dummy channel.", reflect.TypeOf(b.responseWriter))
	return nil, nil, fmt.Errorf("The response writer that was wrapped in this proxy, does not implement http.Hijacker. It is of type: %v", reflect.TypeOf(b.responseWriter))
}

type SizeErrHandler struct {
}

func (e *SizeErrHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, err error) {
	if _, ok := err.(*multibuf.MaxSizeReachedError); ok {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		w.Write([]byte(http.StatusText(http.StatusRequestEntityTooLarge)))
		return
	}
	utils.DefaultHandler.ServeHTTP(w, req, err)
}
