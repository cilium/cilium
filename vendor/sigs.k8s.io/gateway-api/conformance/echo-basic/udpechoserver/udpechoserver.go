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

// Package udpechoserver provides a basic echo server used by Gateway API
// conformance tests. See EchoResponse for the response envelope.
package udpechoserver

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// Context contains information about the pod where the udpechoserver is
// running. It mirrors the fields populated by echo-basic for HTTP responses
// so tests can identify the responding replica.
type Context struct {
	Namespace string `json:"namespace"`
	Ingress   string `json:"ingress"`
	Service   string `json:"service"`
	Pod       string `json:"pod"`
}

// EchoResponse is the JSON envelope this server returns for every datagram
// it receives. It is marshaled and written back to the client on the same
// UDP connection that delivered the request.
//
// The Request field carries the verbatim payload bytes that the client sent,
// allowing tests to assert the server received exactly what was transmitted
// (useful for catching truncation, encoding, or proxy-rewriting issues).
//
// The embedded Context is flattened into the top level of the JSON object via
// the `json:",inline"` tag, so a response looks like:
//
//	{
//	  "request":   "...",
//	  "namespace": "...",
//	  "ingress":   "...",
//	  "service":   "...",
//	  "pod":       "..."
//	}
type EchoResponse struct {
	Request string `json:"request"`
	Context `json:",inline"`
}

// Main starts the UDP echo server on the configured port (UDP_PORT env var,
// default "8080") and runs until a fatal error occurs. It is intended to be
// invoked from echo-basic when UDP_ECHO_SERVER is set.
func Main() {
	port := os.Getenv("UDP_PORT")
	if port == "" {
		port = "8080"
	}
	podContext := Context{
		Namespace: os.Getenv("NAMESPACE"),
		Ingress:   os.Getenv("INGRESS_NAME"),
		Service:   os.Getenv("SERVICE_NAME"),
		Pod:       os.Getenv("POD_NAME"),
	}

	if err := serveUDP(port, podContext); err != nil {
		fmt.Println("echo server error:", err)
		os.Exit(1)
	}
}

// serveUDP listens on the given UDP port and replies to each datagram with a
// JSON-encoded EchoResponse.
func serveUDP(port string, podContext Context) error {
	addr, err := net.ResolveUDPAddr("udp", ":"+port)
	if err != nil {
		return fmt.Errorf("resolving UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listening UDP: %w", err)
	}
	defer conn.Close()

	fmt.Printf("UDP server listening on :%s with context: %+v\n", port, podContext)

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading UDP:", err)
			continue
		}
		fmt.Printf("Received UDP %s from %s\n", string(buffer[:n]), remoteAddr)

		payload, err := json.Marshal(EchoResponse{
			Request: string(buffer[:n]),
			Context: podContext,
		})
		if err != nil {
			fmt.Println("Error marshaling UDP response:", err)
			continue
		}

		if _, err := conn.WriteToUDP(payload, remoteAddr); err != nil {
			fmt.Println("Error writing UDP:", err)
		}
	}
}
