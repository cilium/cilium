package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultSocketPath = "/var/run/cilium/cilium-net.sock"
)

func createUnixURL(path string) string {
	if path != "" && !strings.Contains(path, "://") {
		path = "tcp://" + path
	}
	u, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	// Override URL so that net/http will not complain.
	u.Scheme = "http"
	u.Host = "unix.sock" // Doesn't matter what this is - it's not used.
	u.Path = ""
	urlStr := strings.TrimRight(u.String(), "/")
	return fmt.Sprintf("%s%s", urlStr, path)
}

func NewClient(addr string) *http.Client {
	tr := &http.Transport{
		Dial: func(network, a string) (net.Conn, error) {
			return net.Dial("unix", addr)
		},
	}
	//	cleanhttp.SetTransportFinalizer(tr)
	return &http.Client{Transport: tr}
}

func main() {
	c := NewClient(defaultSocketPath)
	u := createUnixURL("ping")
	var params io.Reader
	req, err := http.NewRequest("GET", u, params)
	if err != nil {
		panic(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Request Ping\n")
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reply: %s\n", string(b))
}
