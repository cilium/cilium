/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tcpserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
)

const (
	WelcomeMessage = "Gateway API Test TCP Server\n"
)

// Context contains the Pod context, to be used on the echo response
type Context struct {
	Namespace string `json:"namespace"`
	Ingress   string `json:"ingress"`
	Service   string `json:"service"`
	Pod       string `json:"pod"`
	TCPPort   string `json:"tcpport"`
	TLSPort   string `json:"tlsport,omitempty,omitzero"`
}

// TLSAssertions contains information about the TLS connection.
type TLSAssertions struct {
	Version            string `json:"version"`
	ServerName         string `json:"serverName"`
	NegotiatedProtocol string `json:"negotiatedProtocol,omitempty,omitzero"`
	Curves             string `json:"curves,omitempty,omitzero"`
	CipherSuite        string `json:"cipherSuite"`
}

// TCPAssertions is the union of Pod context, TLSAssertions and a flag exposing
// if the request came via TLS
type TCPAssertions struct {
	Context      `json:",inline"`
	IsTLS        bool           `json:"isTLS"`
	TLSAssertion *TLSAssertions `json:"tls,omitempty,omitzero"`
}

type tcpServer struct {
	tcpPort   string
	tlsPort   string
	tlsConfig *tls.Config
}

var podContext Context

func Main() {
	ctx := context.Background()
	// We pass the errchan externally, so it can be used to close/stop the server (by unit tests)
	errchan := make(chan error)
	runServer(ctx, errchan)
}

func runServer(ctx context.Context, errchan chan error) {
	podContext = Context{
		Namespace: os.Getenv("NAMESPACE"),
		Ingress:   os.Getenv("INGRESS_NAME"),
		Service:   os.Getenv("SERVICE_NAME"),
		Pod:       os.Getenv("POD_NAME"),
	}

	var err error
	tcpPort := os.Getenv("TCP_PORT")

	if tcpPort == "" {
		tcpPort = "3000"
	} else {
		_, err = strconv.Atoi(tcpPort)
		if err != nil {
			errchan <- fmt.Errorf("non-integer value in TCP_PORT: %s. Error: %w", tcpPort, err)
			return
		}
	}

	podContext.TCPPort = tcpPort

	tlsPort := os.Getenv("TLS_PORT")
	if tlsPort == "" {
		tlsPort = "8443"
	} else {
		_, err = strconv.Atoi(tlsPort)
		if err != nil {
			errchan <- fmt.Errorf("non-integer value in TLS_PORT: %s. Error: %w", tlsPort, err)
			return
		}
	}
	podContext.TLSPort = tlsPort

	tlsConfig, err := newTLSConfig(os.Getenv("TLS_SERVER_CERT"), os.Getenv("TLS_SERVER_PRIV_KEY"))
	if err != nil {
		errchan <- err
		return
	}

	server := tcpServer{
		tcpPort:   tcpPort,
		tlsPort:   tlsPort,
		tlsConfig: tlsConfig,
	}

	go func() {
		slog.Info("Starting server (tcp)", "protocol", "tcp", "port", tcpPort)
		err := server.startListener(ctx, false) //nolint:gosec
		if err != nil {
			errchan <- err
		}
	}()

	if tlsConfig != nil {
		go func() {
			slog.Info("Starting server (tcp)", "protocol", "tls", "port", tlsPort)
			err := server.startListener(ctx, true) //nolint:gosec
			if err != nil {
				errchan <- err
			}
		}()
	}
	if err := <-errchan; err != nil {
		panic(fmt.Sprintf("Failed to start tcp server: %s\n", err.Error()))
	}
}

// start one listener at a time.
func (s *tcpServer) startListener(ctx context.Context, tlsListener bool) error {
	var listener net.Listener
	var err error
	if tlsListener {
		listener, err = tls.Listen("tcp", fmt.Sprintf(":%s", s.tlsPort), s.tlsConfig)
	} else {
		listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf(":%s", s.tcpPort))
	}

	if err != nil {
		return err
	}

	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("Accept error", "error", err)
			continue
		}
		go handleConnection(ctx, conn)
	}
}

func newTLSConfig(serverCertificate, serverPrivateKey string) (*tls.Config, error) {
	// Ignore cases where a cert or key are not set
	if serverCertificate == "" || serverPrivateKey == "" {
		return nil, nil
	}

	certPEM, err := os.ReadFile(serverCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate %s: %w", serverCertificate, err)
	}
	keyPEM, err := os.ReadFile(serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key %s: %w", serverPrivateKey, err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("error parsing key pair: %w", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return tlsConfig, nil
}

// handleConnection will receive a new TCP connection and verify its properties +
// the user request, providing a proper answer that can be asserted by the client
func handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	assertions := &TCPAssertions{
		Context: podContext,
	}

	tlsConn, isTLS := conn.(*tls.Conn)
	// set additional TLS context
	if isTLS {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			slog.Error("TLS Handshake failed", "error", err)
			return
		}

		state := tlsConn.ConnectionState()
		assertions.TLSAssertion = &TLSAssertions{
			NegotiatedProtocol: state.NegotiatedProtocol,
			ServerName:         state.ServerName,
			Version:            tls.VersionName(state.Version),
			CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
			Curves:             state.CurveID.String(),
		}
	}

	assertions.IsTLS = isTLS
	fmt.Fprint(conn, (WelcomeMessage))

	testPayload, err := json.Marshal(assertions)
	if err != nil {
		slog.Error("error encoding tcp response", "error", err)
		return
	}

	// Echo Loop
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		text := scanner.Text()
		switch text {
		// If the client sends a TEST message, answer with the echo-basic payload
		case "TEST":
			fmt.Fprintf(conn, "%s\n", string(testPayload))
		// IS_TLS simple returns a true/false if the connection was made via TLS
		case "IS_TLS":
			fmt.Fprintf(conn, "%t\n", isTLS)
		// PING can be used for simple tests that needs to check the connection state
		case "PING":
			fmt.Fprintf(conn, "PONG\n")
		}
	}
}
