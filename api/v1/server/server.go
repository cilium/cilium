package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-openapi/runtime/flagext"
	"github.com/go-openapi/swag"
	flags "github.com/jessevdk/go-flags"
	graceful "github.com/tylerb/graceful"

	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/common"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	schemeUnix  = "unix"
)

var defaultSchemes []string

func init() {
	defaultSchemes = []string{
		schemeUnix,
	}
}

// NewServer creates a new api cilium server but does not configure it
func NewServer(api *restapi.CiliumAPI) *Server {
	s := new(Server)

	s.api = api
	return s
}

// ConfigureAPI configures the API and handlers.
func (s *Server) ConfigureAPI() {
	if s.api != nil {
		s.handler = configureAPI(s.api)
	}
}

// ConfigureFlags configures the additional flags defined by the handlers. Needs to be called before the parser.Parse
func (s *Server) ConfigureFlags() {
	if s.api != nil {
		configureFlags(s.api)
	}
}

// Server for the cilium API
type Server struct {
	EnabledListeners []string         `long:"scheme" description:"the listeners to enable, this can be repeated and defaults to the schemes in the swagger spec"`
	CleanupTimeout   time.Duration    `long:"cleanup-timeout" description:"grace period for which to wait before shutting down the server" default:"10s"`
	MaxHeaderSize    flagext.ByteSize `long:"max-header-size" description:"controls the maximum number of bytes the server will read parsing the request header's keys and values, including the request line. It does not limit the size of the request body." default:"1MiB"`

	SocketPath    flags.Filename `long:"socket-path" description:"the unix socket to listen on" default:"/var/run/cilium.sock"`
	domainSocketL net.Listener

	Host         string        `long:"host" description:"the IP to listen on" default:"localhost" env:"HOST"`
	Port         int           `long:"port" description:"the port to listen on for insecure connections, defaults to a random value" env:"PORT"`
	ListenLimit  int           `long:"listen-limit" description:"limit the number of outstanding requests"`
	KeepAlive    time.Duration `long:"keep-alive" description:"sets the TCP keep-alive timeouts on accepted connections. It prunes dead TCP connections ( e.g. closing laptop mid-download)" default:"3m"`
	ReadTimeout  time.Duration `long:"read-timeout" description:"maximum duration before timing out read of the request" default:"30s"`
	WriteTimeout time.Duration `long:"write-timeout" description:"maximum duration before timing out write of the response" default:"60s"`
	httpServerL  net.Listener

	TLSHost           string         `long:"tls-host" description:"the IP to listen on for tls, when not specified it's the same as --host" env:"TLS_HOST"`
	TLSPort           int            `long:"tls-port" description:"the port to listen on for secure connections, defaults to a random value" env:"TLS_PORT"`
	TLSCertificate    flags.Filename `long:"tls-certificate" description:"the certificate to use for secure connections" env:"TLS_CERTIFICATE"`
	TLSCertificateKey flags.Filename `long:"tls-key" description:"the private key to use for secure conections" env:"TLS_PRIVATE_KEY"`
	TLSCACertificate  flags.Filename `long:"tls-ca" description:"the certificate authority file to be used with mutual tls auth" env:"TLS_CA_CERTIFICATE"`
	TLSListenLimit    int            `long:"tls-listen-limit" description:"limit the number of outstanding requests"`
	TLSKeepAlive      time.Duration  `long:"tls-keep-alive" description:"sets the TCP keep-alive timeouts on accepted connections. It prunes dead TCP connections ( e.g. closing laptop mid-download)"`
	TLSReadTimeout    time.Duration  `long:"tls-read-timeout" description:"maximum duration before timing out read of the request"`
	TLSWriteTimeout   time.Duration  `long:"tls-write-timeout" description:"maximum duration before timing out write of the response"`
	httpsServerL      net.Listener

	api          *restapi.CiliumAPI
	handler      http.Handler
	hasListeners bool
}

// Logf logs message either via defined user logger or via system one if no user logger is defined.
func (s *Server) Logf(f string, args ...interface{}) {
	if s.api != nil && s.api.Logger != nil {
		s.api.Logger(f, args...)
	} else {
		log.Printf(f, args...)
	}
}

// Fatalf logs message either via defined user logger or via system one if no user logger is defined.
// Exits with non-zero status after printing
func (s *Server) Fatalf(f string, args ...interface{}) {
	if s.api != nil && s.api.Logger != nil {
		s.api.Logger(f, args...)
		os.Exit(1)
	} else {
		log.Fatalf(f, args...)
	}
}

// SetAPI configures the server with the specified API. Needs to be called before Serve
func (s *Server) SetAPI(api *restapi.CiliumAPI) {
	if api == nil {
		s.api = nil
		s.handler = nil
		return
	}

	s.api = api
	s.api.Logger = log.Printf
	s.handler = configureAPI(api)
}

func (s *Server) hasScheme(scheme string) bool {
	schemes := s.EnabledListeners
	if len(schemes) == 0 {
		schemes = defaultSchemes
	}

	for _, v := range schemes {
		if v == scheme {
			return true
		}
	}
	return false
}

// Serve the api
func (s *Server) Serve() (err error) {
	if !s.hasListeners {
		if err := s.Listen(); err != nil {
			return err
		}
	}

	// set default handler, if none is set
	if s.handler == nil {
		if s.api == nil {
			return errors.New("can't create the default handler, as no api is set")
		}

		s.SetHandler(s.api.Serve(nil))
	}

	var wg sync.WaitGroup

	if s.hasScheme(schemeUnix) {
		domainSocket := &graceful.Server{Server: new(http.Server)}
		domainSocket.MaxHeaderBytes = int(s.MaxHeaderSize)
		domainSocket.Handler = s.handler
		domainSocket.LogFunc = s.Logf
		if int64(s.CleanupTimeout) > 0 {
			domainSocket.Timeout = s.CleanupTimeout
		}

		configureServer(domainSocket, "unix")

		if os.Getuid() == 0 {
			socketPath := string(s.SocketPath)
			gid, err := common.GetGroupIDByName(common.CiliumGroupName)
			if err != nil {
				s.Logf("Group %s not found: %s", common.CiliumGroupName, err)
			} else {
				if err := os.Chown(socketPath, 0, gid); err != nil {
					return fmt.Errorf("failed while setting up %s's group ID"+
						" in %q: %s", common.CiliumGroupName, socketPath, err)
				}
			}
			if err := os.Chmod(socketPath, 0660); err != nil {
				return fmt.Errorf("failed while setting up %s's file"+
					" permissions in %q: %s", common.CiliumGroupName, socketPath, err)
			}
		}

		wg.Add(1)
		s.Logf("Serving cilium at unix://%s", s.SocketPath)
		go func(l net.Listener) {
			defer wg.Done()
			if err := domainSocket.Serve(l); err != nil {
				s.Fatalf("%v", err)
			}
			s.Logf("Stopped serving cilium at unix://%s", s.SocketPath)
		}(s.domainSocketL)
	}

	if s.hasScheme(schemeHTTP) {
		httpServer := &graceful.Server{Server: new(http.Server)}
		httpServer.MaxHeaderBytes = int(s.MaxHeaderSize)
		httpServer.ReadTimeout = s.ReadTimeout
		httpServer.WriteTimeout = s.WriteTimeout
		httpServer.SetKeepAlivesEnabled(int64(s.KeepAlive) > 0)
		httpServer.TCPKeepAlive = s.KeepAlive
		if s.ListenLimit > 0 {
			httpServer.ListenLimit = s.ListenLimit
		}

		if int64(s.CleanupTimeout) > 0 {
			httpServer.Timeout = s.CleanupTimeout
		}

		httpServer.Handler = s.handler
		httpServer.LogFunc = s.Logf

		configureServer(httpServer, "http")

		wg.Add(1)
		s.Logf("Serving cilium at http://%s", s.httpServerL.Addr())
		go func(l net.Listener) {
			defer wg.Done()
			if err := httpServer.Serve(l); err != nil {
				s.Fatalf("%v", err)
			}
			s.Logf("Stopped serving cilium at http://%s", l.Addr())
		}(s.httpServerL)
	}

	if s.hasScheme(schemeHTTPS) {
		httpsServer := &graceful.Server{Server: new(http.Server)}
		httpsServer.MaxHeaderBytes = int(s.MaxHeaderSize)
		httpsServer.ReadTimeout = s.TLSReadTimeout
		httpsServer.WriteTimeout = s.TLSWriteTimeout
		httpsServer.SetKeepAlivesEnabled(int64(s.TLSKeepAlive) > 0)
		httpsServer.TCPKeepAlive = s.TLSKeepAlive
		if s.TLSListenLimit > 0 {
			httpsServer.ListenLimit = s.TLSListenLimit
		}
		if int64(s.CleanupTimeout) > 0 {
			httpsServer.Timeout = s.CleanupTimeout
		}
		httpsServer.Handler = s.handler
		httpsServer.LogFunc = s.Logf

		// Inspired by https://blog.bracebin.com/achieving-perfect-ssl-labs-score-with-go
		httpsServer.TLSConfig = &tls.Config{
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			// Only use curves which have assembly implementations
			// https://github.com/golang/go/tree/master/src/crypto/elliptic
			CurvePreferences: []tls.CurveID{tls.CurveP256},
			// Use modern tls mode https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
			NextProtos: []string{"http/1.1", "h2"},
			// https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Rule_-_Only_Support_Strong_Protocols
			MinVersion: tls.VersionTLS12,
			// These ciphersuites support Forward Secrecy: https://en.wikipedia.org/wiki/Forward_secrecy
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		if s.TLSCertificate != "" && s.TLSCertificateKey != "" {
			httpsServer.TLSConfig.Certificates = make([]tls.Certificate, 1)
			httpsServer.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(string(s.TLSCertificate), string(s.TLSCertificateKey))
		}

		if s.TLSCACertificate != "" {
			caCert, err := ioutil.ReadFile(string(s.TLSCACertificate))
			if err != nil {
				log.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			httpsServer.TLSConfig.ClientCAs = caCertPool
			httpsServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		configureTLS(httpsServer.TLSConfig)
		httpsServer.TLSConfig.BuildNameToCertificate()

		if err != nil {
			return err
		}

		if len(httpsServer.TLSConfig.Certificates) == 0 {
			if s.TLSCertificate == "" {
				if s.TLSCertificateKey == "" {
					s.Fatalf("the required flags `--tls-certificate` and `--tls-key` were not specified")
				}
				s.Fatalf("the required flag `--tls-certificate` was not specified")
			}
			if s.TLSCertificateKey == "" {
				s.Fatalf("the required flag `--tls-key` was not specified")
			}
		}

		configureServer(httpsServer, "https")

		wg.Add(1)
		s.Logf("Serving cilium at https://%s", s.httpsServerL.Addr())
		go func(l net.Listener) {
			defer wg.Done()
			if err := httpsServer.Serve(l); err != nil {
				s.Fatalf("%v", err)
			}
			s.Logf("Stopped serving cilium at https://%s", l.Addr())
		}(tls.NewListener(s.httpsServerL, httpsServer.TLSConfig))
	}

	wg.Wait()
	return nil
}

// Listen creates the listeners for the server
func (s *Server) Listen() error {
	if s.hasListeners { // already done this
		return nil
	}

	if s.hasScheme(schemeHTTPS) {
		// Use http host if https host wasn't defined
		if s.TLSHost == "" {
			s.TLSHost = s.Host
		}
		// Use http listen limit if https listen limit wasn't defined
		if s.TLSListenLimit == 0 {
			s.TLSListenLimit = s.ListenLimit
		}
		// Use http tcp keep alive if https tcp keep alive wasn't defined
		if int64(s.TLSKeepAlive) == 0 {
			s.TLSKeepAlive = s.KeepAlive
		}
		// Use http read timeout if https read timeout wasn't defined
		if int64(s.TLSReadTimeout) == 0 {
			s.TLSReadTimeout = s.ReadTimeout
		}
		// Use http write timeout if https write timeout wasn't defined
		if int64(s.TLSWriteTimeout) == 0 {
			s.TLSWriteTimeout = s.WriteTimeout
		}
	}

	if s.hasScheme(schemeUnix) {
		domSockListener, err := net.Listen("unix", string(s.SocketPath))
		if err != nil {
			return err
		}
		s.domainSocketL = domSockListener
	}

	if s.hasScheme(schemeHTTP) {
		listener, err := net.Listen("tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
		if err != nil {
			return err
		}

		h, p, err := swag.SplitHostPort(listener.Addr().String())
		if err != nil {
			return err
		}
		s.Host = h
		s.Port = p
		s.httpServerL = listener
	}

	if s.hasScheme(schemeHTTPS) {
		tlsListener, err := net.Listen("tcp", net.JoinHostPort(s.TLSHost, strconv.Itoa(s.TLSPort)))
		if err != nil {
			return err
		}

		sh, sp, err := swag.SplitHostPort(tlsListener.Addr().String())
		if err != nil {
			return err
		}
		s.TLSHost = sh
		s.TLSPort = sp
		s.httpsServerL = tlsListener
	}

	s.hasListeners = true
	return nil
}

// Shutdown server and clean up resources
func (s *Server) Shutdown() error {
	s.api.ServerShutdown()
	return nil
}

// GetHandler returns a handler useful for testing
func (s *Server) GetHandler() http.Handler {
	return s.handler
}

// SetHandler allows for setting a http handler on this server
func (s *Server) SetHandler(handler http.Handler) {
	s.handler = handler
}

// UnixListener returns the domain socket listener
func (s *Server) UnixListener() (net.Listener, error) {
	if !s.hasListeners {
		if err := s.Listen(); err != nil {
			return nil, err
		}
	}
	return s.domainSocketL, nil
}

// HTTPListener returns the http listener
func (s *Server) HTTPListener() (net.Listener, error) {
	if !s.hasListeners {
		if err := s.Listen(); err != nil {
			return nil, err
		}
	}
	return s.httpServerL, nil
}

// TLSListener returns the https listener
func (s *Server) TLSListener() (net.Listener, error) {
	if !s.hasListeners {
		if err := s.Listen(); err != nil {
			return nil, err
		}
	}
	return s.httpsServerL, nil
}
