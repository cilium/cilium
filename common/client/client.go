package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	common "github.com/noironetworks/cilium-net/common"

	l "github.com/op/go-logging"
)

var log = l.MustGetLogger("cilium-net-client")

func init() {
	common.SetupLOG(log, "DEBUG", "")
}

// Client has the internal details necessary to talk with the daemon.
type Client struct {
	proto      string
	addr       string
	basePath   string
	scheme     string
	tlsConfig  *tls.Config
	httpClient *http.Client
}

// NewDefaultClient creates and returns a client that will talk with common.CiliumStock.
func NewDefaultClient() (*Client, error) {
	return NewClient("unix://"+common.CiliumSock, nil, nil, nil)
}

// NewClient creates and returns a client that will send requests to host, using the
// http.Client httpCli with transport and httpHeaders.
func NewClient(host string, httpCli *http.Client, transport *http.Transport, httpHeaders map[string]string) (*Client, error) {
	var (
		basePath       string
		tlsConfig      *tls.Config
		scheme         = "http"
		protoAddrParts = strings.SplitN(host, "://", 2)
		proto, addr    = protoAddrParts[0], protoAddrParts[1]
	)

	if proto == "tcp" {
		parsed, err := url.Parse("tcp://" + addr)
		if err != nil {
			return nil, err
		}
		addr = parsed.Host
		basePath = parsed.Path
	}

	transport = configureTransport(transport, proto, addr)
	if transport.TLSClientConfig != nil {
		scheme = "https"
	}

	if httpCli != nil {
		httpCli.Transport = transport
	} else {
		httpCli = &http.Client{Transport: transport}
	}

	log.Infof("Client talking with host: %s", host)

	return &Client{
		proto:      proto,
		addr:       addr,
		basePath:   basePath,
		scheme:     scheme,
		tlsConfig:  tlsConfig,
		httpClient: httpCli,
	}, nil
}

func (cli *Client) getAPIPath(p string, query url.Values) string {
	apiPath := fmt.Sprintf("%s%s", cli.basePath, p)
	if len(query) > 0 {
		apiPath += "?" + query.Encode()
	}
	return apiPath
}

func configureTransport(tr *http.Transport, proto, addr string) *http.Transport {
	if tr == nil {
		tr = &http.Transport{}
	}

	if proto == "unix" {
		// No need for compression in local communications.
		tr.DisableCompression = true
		tr.Dial = func(_, _ string) (net.Conn, error) {
			return net.Dial(proto, addr)
		}
	} else {
		tr.Proxy = http.ProxyFromEnvironment
		tr.Dial = (&net.Dialer{}).Dial
	}

	return tr
}
