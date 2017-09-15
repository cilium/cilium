// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// TLSClientOptions to configure client authentication with mutual TLS
type TLSClientOptions struct {
	Certificate        string
	Key                string
	CA                 string
	ServerName         string
	InsecureSkipVerify bool
	_                  struct{}
}

// TLSClientAuth creates a tls.Config for mutual auth
func TLSClientAuth(opts TLSClientOptions) (*tls.Config, error) {
	// load client cert
	cert, err := tls.LoadX509KeyPair(opts.Certificate, opts.Key)
	if err != nil {
		return nil, fmt.Errorf("tls client cert: %v", err)
	}

	// create client tls config
	cfg := &tls.Config{}
	cfg.Certificates = []tls.Certificate{cert}
	cfg.InsecureSkipVerify = opts.InsecureSkipVerify

	// When no CA certificate is provided, default to the system cert pool
	// that way when a request is made to a server known by the system trust store,
	// the name is still verified
	if opts.CA != "" {
		// load ca cert
		caCert, err := ioutil.ReadFile(opts.CA)
		if err != nil {
			return nil, fmt.Errorf("tls client ca: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		cfg.RootCAs = caCertPool
	}

	// apply servername overrride
	if opts.ServerName != "" {
		cfg.InsecureSkipVerify = false
		cfg.ServerName = opts.ServerName
	}

	cfg.BuildNameToCertificate()

	return cfg, nil
}

// TLSTransport creates a http client transport suitable for mutual tls auth
func TLSTransport(opts TLSClientOptions) (http.RoundTripper, error) {
	cfg, err := TLSClientAuth(opts)
	if err != nil {
		return nil, err
	}

	return &http.Transport{TLSClientConfig: cfg}, nil
}

// TLSClient creates a http.Client for mutual auth
func TLSClient(opts TLSClientOptions) (*http.Client, error) {
	transport, err := TLSTransport(opts)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport}, nil
}

// DefaultTimeout the default request timeout
var DefaultTimeout = 30 * time.Second

// Runtime represents an API client that uses the transport
// to make http requests based on a swagger specification.
type Runtime struct {
	DefaultMediaType      string
	DefaultAuthentication runtime.ClientAuthInfoWriter
	Consumers             map[string]runtime.Consumer
	Producers             map[string]runtime.Producer

	Transport http.RoundTripper
	Jar       http.CookieJar
	//Spec      *spec.Document
	Host     string
	BasePath string
	Formats  strfmt.Registry
	Debug    bool
	Context  context.Context

	clientOnce *sync.Once
	client     *http.Client
	schemes    []string
	do         func(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error)
}

// New creates a new default runtime for a swagger api runtime.Client
func New(host, basePath string, schemes []string) *Runtime {
	var rt Runtime
	rt.DefaultMediaType = runtime.JSONMime

	// TODO: actually infer this stuff from the spec
	rt.Consumers = map[string]runtime.Consumer{
		runtime.JSONMime:    runtime.JSONConsumer(),
		runtime.XMLMime:     runtime.XMLConsumer(),
		runtime.TextMime:    runtime.TextConsumer(),
		runtime.DefaultMime: runtime.ByteStreamConsumer(),
	}
	rt.Producers = map[string]runtime.Producer{
		runtime.JSONMime:    runtime.JSONProducer(),
		runtime.XMLMime:     runtime.XMLProducer(),
		runtime.TextMime:    runtime.TextProducer(),
		runtime.DefaultMime: runtime.ByteStreamProducer(),
	}
	rt.Transport = http.DefaultTransport
	rt.Jar = nil
	rt.Host = host
	rt.BasePath = basePath
	rt.Context = context.Background()
	rt.clientOnce = new(sync.Once)
	if !strings.HasPrefix(rt.BasePath, "/") {
		rt.BasePath = "/" + rt.BasePath
	}
	rt.Debug = len(os.Getenv("DEBUG")) > 0
	if len(schemes) > 0 {
		rt.schemes = schemes
	}
	rt.do = ctxhttp.Do
	return &rt
}

// NewWithClient allows you to create a new transport with a configured http.Client
func NewWithClient(host, basePath string, schemes []string, client *http.Client) *Runtime {
	rt := New(host, basePath, schemes)
	if client != nil {
		rt.clientOnce.Do(func() {
			rt.client = client
		})
	}
	return rt
}

func (r *Runtime) pickScheme(schemes []string) string {
	if v := r.selectScheme(r.schemes); v != "" {
		return v
	}
	if v := r.selectScheme(schemes); v != "" {
		return v
	}
	return "http"
}

func (r *Runtime) selectScheme(schemes []string) string {
	schLen := len(schemes)
	if schLen == 0 {
		return ""
	}

	scheme := schemes[0]
	// prefer https, but skip when not possible
	if scheme != "https" && schLen > 1 {
		for _, sch := range schemes {
			if sch == "https" {
				scheme = sch
				break
			}
		}
	}
	return scheme
}

// Submit a request and when there is a body on success it will turn that into the result
// all other things are turned into an api error for swagger which retains the status code
func (r *Runtime) Submit(operation *runtime.ClientOperation) (interface{}, error) {
	params, readResponse, auth := operation.Params, operation.Reader, operation.AuthInfo

	request, err := newRequest(operation.Method, operation.PathPattern, params)
	if err != nil {
		return nil, err
	}

	var accept []string
	accept = append(accept, operation.ProducesMediaTypes...)
	if err = request.SetHeaderParam(runtime.HeaderAccept, accept...); err != nil {
		return nil, err
	}

	if auth == nil && r.DefaultAuthentication != nil {
		auth = r.DefaultAuthentication
	}
	if auth != nil {
		if err := auth.AuthenticateRequest(request, r.Formats); err != nil {
			return nil, err
		}
	}

	// TODO: pick appropriate media type
	cmt := r.DefaultMediaType
	for _, mediaType := range operation.ConsumesMediaTypes {
		// Pick first non-empty media type
		if mediaType != "" {
			cmt = mediaType
			break
		}
	}

	req, err := request.BuildHTTP(cmt, r.Producers, r.Formats)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = r.pickScheme(operation.Schemes)
	req.URL.Host = r.Host
	var reinstateSlash bool
	if req.URL.Path != "" && req.URL.Path != "/" && req.URL.Path[len(req.URL.Path)-1] == '/' {
		reinstateSlash = true
	}
	req.URL.Path = path.Join(r.BasePath, req.URL.Path)
	if reinstateSlash {
		req.URL.Path = req.URL.Path + "/"
	}

	r.clientOnce.Do(func() {
		r.client = &http.Client{
			Transport: r.Transport,
			Jar:       r.Jar,
		}
	})

	if r.Debug {
		b, err2 := httputil.DumpRequestOut(req, true)
		if err2 != nil {
			return nil, err2
		}
		fmt.Fprintln(os.Stderr, string(b))
	}

	var hasTimeout bool
	pctx := operation.Context
	if pctx == nil {
		pctx = r.Context
	} else {
		hasTimeout = true
	}
	if pctx == nil {
		pctx = context.Background()
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if hasTimeout {
		ctx, cancel = context.WithCancel(pctx)
	} else {
		ctx, cancel = context.WithTimeout(pctx, request.timeout)
	}
	defer cancel()

	client := operation.Client
	if client == nil {
		client = r.client
	}
	if r.do == nil {
		r.do = ctxhttp.Do
	}
	res, err := r.do(ctx, client, req) // make requests, by default follows 10 redirects before failing
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if r.Debug {
		b, err2 := httputil.DumpResponse(res, true)
		if err2 != nil {
			return nil, err2
		}
		fmt.Fprintln(os.Stderr, string(b))
	}

	ct := res.Header.Get(runtime.HeaderContentType)
	if ct == "" { // this should really really never occur
		ct = r.DefaultMediaType
	}

	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, fmt.Errorf("parse content type: %s", err)
	}

	cons, ok := r.Consumers[mt]
	if !ok {
		// scream about not knowing what to do
		return nil, fmt.Errorf("no consumer: %q", ct)
	}
	return readResponse.ReadResponse(response{res}, cons)
}
