// package forwarder implements http handler that forwards requests to remote server
// and serves back the response
// websocket proxying support based on https://github.com/yhat/wsutil
package forward

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/vulcand/oxy/utils"
	"net/http/httputil"
)

// ReqRewriter can alter request headers and body
type ReqRewriter interface {
	Rewrite(r *http.Request)
}

type optSetter func(f *Forwarder) error

// PassHostHeader specifies if a client's Host header field should
// be delegated
func PassHostHeader(b bool) optSetter {
	return func(f *Forwarder) error {
		f.httpForwarder.passHost = b
		return nil
	}
}

// RoundTripper sets a new http.RoundTripper
// Forwarder will use http.DefaultTransport as a default round tripper
func RoundTripper(r http.RoundTripper) optSetter {
	return func(f *Forwarder) error {
		f.roundTripper = r
		return nil
	}
}

// Dialer mirrors the net.Dial function to be able to define alternate
// implementations
type Dialer func(network, address string) (net.Conn, error)

// WebsocketDial defines a new network dialer to use to dial to remote websocket destination.
// If no dialer has been defined, net.Dial will be used.
func WebsocketDial(dial Dialer) optSetter {
	return func(f *Forwarder) error {
		f.websocketForwarder.dial = dial
		return nil
	}
}

// Rewriter defines a request rewriter for the HTTP forwarder
func Rewriter(r ReqRewriter) optSetter {
	return func(f *Forwarder) error {
		f.httpForwarder.rewriter = r
		return nil
	}
}

// WebsocketRewriter defines a request rewriter for the websocket forwarder
func WebsocketRewriter(r ReqRewriter) optSetter {
	return func(f *Forwarder) error {
		f.websocketForwarder.rewriter = r
		return nil
	}
}

// ErrorHandler is a functional argument that sets error handler of the server
func ErrorHandler(h utils.ErrorHandler) optSetter {
	return func(f *Forwarder) error {
		f.errHandler = h
		return nil
	}
}

// Logger specifies the logger to use.
// Forwarder will default to oxyutils.NullLogger if no logger has been specified
func Stream(stream bool) optSetter {
	return func(f *Forwarder) error {
		f.stream = stream
		return nil
	}
}

func StateListener(stateListener UrlForwardingStateListener) optSetter {
	return func(f *Forwarder) error {
		f.stateListener = stateListener
		return nil
	}
}

func StreamingFlushInterval(flushInterval time.Duration) optSetter {
	return func(f *Forwarder) error {
		f.httpStreamingForwarder.flushInterval = flushInterval
		return nil
	}
}

// Forwarder wraps two traffic forwarding implementations: HTTP and websockets.
// It decides based on the specified request which implementation to use
type Forwarder struct {
	*httpForwarder
	*httpStreamingForwarder
	*websocketForwarder
	*handlerContext
	stateListener UrlForwardingStateListener
	stream        bool
}

// handlerContext defines a handler context for error reporting and logging
type handlerContext struct {
	errHandler utils.ErrorHandler
}

// httpForwarder is a handler that can reverse proxy
// HTTP traffic
type httpForwarder struct {
	roundTripper http.RoundTripper
	rewriter     ReqRewriter
	passHost     bool
}

// httpStreamingForwarder is a handler that can reverse proxy
// HTTP traffic but doesn't wait for a complete
// response before it begins writing bytes upstream
type httpStreamingForwarder struct {
	rewriter      ReqRewriter
	passHost      bool
	flushInterval time.Duration
}

// websocketForwarder is a handler that can reverse proxy
// websocket traffic
type websocketForwarder struct {
	dial            Dialer
	rewriter        ReqRewriter
	TLSClientConfig *tls.Config
}

const (
	StateConnected = iota
	StateDisconnected
)

type UrlForwardingStateListener func(*url.URL, int)

// New creates an instance of Forwarder based on the provided list of configuration options
func New(setters ...optSetter) (*Forwarder, error) {
	f := &Forwarder{
		httpForwarder:          &httpForwarder{},
		httpStreamingForwarder: &httpStreamingForwarder{flushInterval: time.Duration(100) * time.Millisecond},
		websocketForwarder:     &websocketForwarder{},
		handlerContext:         &handlerContext{},
	}
	for _, s := range setters {
		if err := s(f); err != nil {
			return nil, err
		}
	}
	if f.httpForwarder.roundTripper == nil {
		f.httpForwarder.roundTripper = http.DefaultTransport
	}
	if f.websocketForwarder.dial == nil {
		f.websocketForwarder.dial = net.Dial
	}
	if f.httpForwarder.rewriter == nil {
		h, err := os.Hostname()
		if err != nil {
			h = "localhost"
		}
		f.httpForwarder.rewriter = &HeaderRewriter{TrustForwardHeader: true, Hostname: h}
	}
	if f.errHandler == nil {
		f.errHandler = utils.DefaultHandler
	}
	return f, nil
}

// ServeHTTP decides which forwarder to use based on the specified
// request and delegates to the proper implementation
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if f.stateListener != nil {
		f.stateListener(req.URL, StateConnected)
		defer f.stateListener(req.URL, StateDisconnected)
	}
	if isWebsocketRequest(req) {
		f.websocketForwarder.serveHTTP(w, req, f.handlerContext)
	} else if f.stream {
		f.httpStreamingForwarder.serveHTTP(w, req, f.handlerContext)
	} else {
		f.httpForwarder.serveHTTP(w, req, f.handlerContext)
	}
}

// serveHTTP forwards HTTP traffic using the configured transport
func (f *httpForwarder) serveHTTP(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {

	start := time.Now().UTC()
	response, err := f.roundTripper.RoundTrip(f.copyRequest(req, req.URL))
	if err != nil {
		log.Errorf("Error forwarding to %v, err: %v", req.URL, err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}

	if req.TLS != nil {
		log.Infof("Round trip: %v, code: %v, duration: %v tls:version: %x, tls:resume:%t, tls:csuite:%x, tls:server:%v",
			req.URL, response.StatusCode, time.Now().UTC().Sub(start),
			req.TLS.Version,
			req.TLS.DidResume,
			req.TLS.CipherSuite,
			req.TLS.ServerName)
	} else {
		log.Infof("Round trip: %v, code: %v, duration: %v",
			req.URL, response.StatusCode, time.Now().UTC().Sub(start))
	}

	utils.CopyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)

	written, err := io.Copy(w, response.Body)
	defer response.Body.Close()

	if err != nil {
		log.Errorf("Error copying upstream response Body: %v", err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}

	if written != 0 {
		w.Header().Set(ContentLength, strconv.FormatInt(written, 10))
	}
}

// copyRequest makes a copy of the specified request to be sent using the configured
// transport
func (f *httpForwarder) copyRequest(req *http.Request, u *url.URL) *http.Request {
	outReq := new(http.Request)
	*outReq = *req // includes shallow copies of maps, but we handle this below

	outReq.URL = utils.CopyURL(req.URL)
	outReq.URL.Scheme = u.Scheme
	outReq.URL.Host = u.Host
	outReq.URL.Opaque = req.RequestURI
	// raw query is already included in RequestURI, so ignore it to avoid dupes
	outReq.URL.RawQuery = ""
	// Do not pass client Host header unless optsetter PassHostHeader is set.
	if !f.passHost {
		outReq.Host = u.Host
	}
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1

	// Overwrite close flag so we can keep persistent connection for the backend servers
	outReq.Close = false

	outReq.Header = make(http.Header)
	utils.CopyHeaders(outReq.Header, req.Header)

	if f.rewriter != nil {
		f.rewriter.Rewrite(outReq)
	}
	return outReq
}

// serveHTTP forwards websocket traffic
func (f *websocketForwarder) serveHTTP(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	outReq := f.copyRequest(req)
	host := outReq.URL.Host

	// if host does not specify a port, use the default http port
	if !strings.Contains(host, ":") {
		if outReq.URL.Scheme == "wss" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	targetConn, err := f.dial("tcp", host)
	if err != nil {
		log.Errorf("Error dialing `%v`: %v", host, err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Errorf("Unable to hijack the connection: does not implement http.Hijacker")
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}
	underlyingConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Errorf("Unable to hijack the connection: %v", err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}
	// it is now caller's responsibility to Close the underlying connection
	defer underlyingConn.Close()
	defer targetConn.Close()

	// write the modified incoming request to the dialed connection
	if err = outReq.Write(targetConn); err != nil {
		log.Errorf("Unable to copy request to target: %v", err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}
	errc := make(chan error, 2)
	replicate := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go replicate(targetConn, underlyingConn)
	go replicate(underlyingConn, targetConn)
	<-errc
}

// copyRequest makes a copy of the specified request.
func (f *websocketForwarder) copyRequest(req *http.Request) (outReq *http.Request) {
	outReq = new(http.Request)
	*outReq = *req
	outReq.URL = utils.CopyURL(req.URL)
	outReq.URL.Scheme = req.URL.Scheme
	outReq.URL.Host = req.URL.Host
	return outReq
}

// isWebsocketRequest determines if the specified HTTP request is a
// websocket handshake request
func isWebsocketRequest(req *http.Request) bool {
	containsHeader := func(name, value string) bool {
		items := strings.Split(req.Header.Get(name), ",")
		for _, item := range items {
			if value == strings.ToLower(strings.TrimSpace(item)) {
				return true
			}
		}
		return false
	}
	return containsHeader(Connection, "upgrade") && containsHeader(Upgrade, "websocket")
}

// serveHTTP forwards HTTP traffic using the configured transport
func (f *httpStreamingForwarder) serveHTTP(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	pw := utils.ProxyWriter{
		W: w,
	}
	start := time.Now().UTC()

	reqUrl, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		log.Errorf("Error parsing Request URI %v, err: %v", req.RequestURI, err)
		ctx.errHandler.ServeHTTP(w, req, err)
		return
	}

	urlcpy := utils.CopyURL(req.URL)
	urlcpy.Scheme = req.URL.Scheme
	urlcpy.Host = req.URL.Host

	req.URL.Path = reqUrl.Path
	req.URL.RawQuery = reqUrl.RawQuery

	revproxy := httputil.NewSingleHostReverseProxy(urlcpy)
	revproxy.FlushInterval = f.flushInterval //Flush something every 100 milliseconds
	revproxy.ServeHTTP(w, req)

	if req.TLS != nil {
		log.Infof("Round trip: %v, code: %v, Length: %v, duration: %v tls:version: %x, tls:resume:%t, tls:csuite:%x, tls:server:%v",
			req.URL, pw.Code, pw.Length, time.Now().UTC().Sub(start),
			req.TLS.Version,
			req.TLS.DidResume,
			req.TLS.CipherSuite,
			req.TLS.ServerName)
	} else {
		log.Infof("Round trip: %v, code: %v, Length: %v, duration: %v",
			req.URL, pw.Code, pw.Length, time.Now().UTC().Sub(start))
	}
}
