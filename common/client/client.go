package client

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	common "github.com/noironetworks/cilium-net/common"

	l "github.com/op/go-logging"
	"gopkg.in/resty.v0"
)

var log = l.MustGetLogger("cilium-net-client")

func init() {
	common.SetupLOG(log, "DEBUG")
}

// Client has the internal details necessary to talk with the daemon.
type Client struct {
	*resty.Client
}

// NewDefaultClient creates and returns a client that will talk with common.CiliumStock.
func NewDefaultClient() (*Client, error) {
	return NewClient("unix://"+common.CiliumSock, nil)
}

// NewClient creates and returns a client that will send requests to host, using the
// http.Client httpCli with transport and httpHeaders.
func NewClient(host string, transport *http.Transport) (*Client, error) {

	var (
		httpCli        *http.Client
		protoAddrParts = strings.SplitN(host, "://", 2)
		proto, addr    = protoAddrParts[0], protoAddrParts[1]
	)

	switch proto {
	case "tcp":
		if _, err := url.Parse("tcp://" + addr); err != nil {
			return nil, err
		}
		addr = "http://" + addr
	case "http":
		addr = "http://" + addr
	}

	transport = configureTransport(transport, proto, addr)

	if httpCli != nil {
		httpCli.Transport = transport
	} else {
		httpCli = &http.Client{Transport: transport}
	}

	r := resty.New().SetTransport(transport).SetScheme("http").SetCloseConnection(true)
	if proto != "unix" {
		r.SetHostURL(addr)
	}

	log.Debugf("Client talking with host: %s", host)
	return &Client{
		r,
	}, nil
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
