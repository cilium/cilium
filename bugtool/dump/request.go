// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// Request implements a Task that makes HTTP requests over either a network
// or unix socket.
type Request struct {
	base `mapstructure:",squash"`
	// URL is the url to be passed to the request.
	URL string
	// UnixSocketPath denotes optional unix socket to use for request, if not empty
	// then client transport will be configured to use this.
	UnixSocketPath string
	// OnSocketExist denotes that the request should only be run and/or be reported
	// as a failure if the UnixSocketPath exists.
	OnSocketExist bool
}

func (r *Request) Validate(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return fmt.Errorf("invalid request %q: %w", r.Name, err)
	}
	return nil
}

// NewRequest constructs a new Request.
func NewRequest(name, url string) *Request {
	return &Request{
		base: base{
			Kind: "Request",
			Name: name,
		},
		URL: url,
	}
}

// WithUnixSocket returns a request that will use a unix socket.
func (r *Request) WithUnixSocket(socketPath string) *Request {
	nr := *r
	nr.UnixSocketPath = socketPath
	return &nr
}

// WithUnixSocketExists returns a request that will use a unix socket,
// if the socket file exists.
func (r *Request) WithUnixSocketExists(socketPath string) *Request {
	nr := r.WithUnixSocket(socketPath)
	nr.OnSocketExist = true
	return nr
}

func (r *Request) getClient() *http.Client {
	if r.UnixSocketPath != "" {
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", r.UnixSocketPath)
				},
			},
		}
	}
	return http.DefaultClient
}

// Run runs the request.
func (r *Request) Run(ctx context.Context, runtime Context) error {
	return runtime.SubmitFn(r.Identifier(), func(ctx context.Context) error {
		if r.UnixSocketPath != "" {
			_, err := os.Stat(r.UnixSocketPath)
			if err != nil && os.IsNotExist(err) && r.OnSocketExist {
				log.WithFields(log.Fields{
					"name":   r.Name,
					"url":    r.URL,
					"socket": r.UnixSocketPath,
				}).Info("no unix socket file exists skipping due to OnSocketExist=true")
				return nil
			} else if err != nil {
				return err
			}
		}
		file := filepath.Join(runtime.Dir(), r.GetName())
		headersFile := file + "_headers.json"
		return downloadToFile(ctx, r.getClient(), r.URL, file, headersFile)
	})
}

func downloadToFile(ctx context.Context, client *http.Client, url, file, headersfile string) error {
	log.Debugf("requesting from: %s", url)
	l := log.WithFields(log.Fields{
		"url":  url,
		"file": file,
	})

	fd, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("failed to create request body file: %w", err)
	}
	out := createErrFile(file, fd)
	defer out.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	l.Debug("doing http request")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	fd, err = os.Create(headersfile)
	if err != nil {
		return fmt.Errorf("failed to create request headers file: %w", err)
	}
	hdrs := createErrFile(file, fd)
	defer func() {
		if err := json.NewEncoder(hdrs).Encode(resp.Header); err != nil {
			log.Error("failed to write request headers: %s", err)
		}
		hdrs.Close()
	}()

	l.Debug("reading request body")

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	return err
}
