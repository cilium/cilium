// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"log/slog"
	"sync"

	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/lock"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

// connectionManager manages the gRPC connection to the Cilium agent.
// It provides thread-safe access to the connection and client.
// It uses a condition variable and an event channel to signal changes to the connection state.
//
// | Method                | What it does                                                                                  | When to call / Who calls it                  |
// |---------------------- |-----------------------------------------------------------------------------------------------|----------------------------------------------|
// | getFqdnClientWithRev  | Waits for a connection, returns client and revision                                           | Callers needing a valid client (e.g. RPCs)   |
// | updateConnection      | Updates connection/client, increments revision, emits event, notifies waiters                 | When a new connection is established         |
// | removeConnection      | Removes connection/client if revision matches, increments revision, emits event, notifies     | When connection is lost                      |
// | Close                 | Closes connection/client, increments revision, emits event, notifies waiters                  | When shutting down or cleaning up            |
// | isConnected           | Returns true if connection is established                                                     | To check connection status                   |
// | Events                | Returns a channel emitting connection events                                                  | For observers to react to connection changes |
type connectionManager struct {
	logger *slog.Logger
	// mu is a mutex for synchronizing access to the connection and client
	mu lock.RWMutex
	// connMu is a mutex for synchronizing access to the condition variable
	connMu lock.Mutex
	// connCond is a conditional variable for signaling changes to the connection state
	connCond *sync.Cond
	// connection is the gRPC client connection to the Cilium agent
	connection *grpc.ClientConn
	// fqdnClient is the gRPC client for FQDN data
	fqdnClient pb.FQDNDataClient
	// revision is a monotonically increasing connection revision
	revision uint64
	// events provides a channel that emits connection events
	events chan connEvent
}

type connEvent struct {
	Connected bool
	Rev       uint64
}

func newConnectionManager(logger *slog.Logger) *connectionManager {
	cm := &connectionManager{
		events: make(chan connEvent, 1),
		logger: logger,
	}
	cm.connCond = sync.NewCond(&cm.connMu)
	return cm
}

func (cm *connectionManager) emit(ce connEvent) {
	select {
	case cm.events <- ce:
	default:
		<-cm.events
		cm.events <- ce
	}
}

// Events returns a receive-only channel of connection events for observers.
func (cm *connectionManager) Events() <-chan connEvent {
	return cm.events
}

// getFqdnClientWithRev returns the current gRPC client and its revision.
// If no connection exists, it waits until a connection is established.
// Why we return the revision:
// The revision is incremented every time the underlying connection is
// replaced or cleared. Callers that obtain (client, rev) use that same
// rev later when reporting a connection-level failure via
// removeConnection(rev). removeConnection only tears down the connection
// if the revision still matches, preventing a race where an older
// goroutine (using a stale connection) closes a newer healthy connection
// that was established after it started. This guards against stale
// close/removal and ensures only the connection instance actually used
// by the caller is eligible for removal.
func (cm *connectionManager) getFqdnClientWithRev() (pb.FQDNDataClient, uint64, error) {
	cm.connMu.Lock()
	for cm.connection == nil {
		cm.connCond.Wait()
	}
	cm.mu.RLock()
	client := cm.fqdnClient
	rev := cm.revision
	cm.mu.RUnlock()
	cm.connMu.Unlock()
	if client == nil {
		return nil, 0, fmt.Errorf("gRPC client not connected")
	}
	return client, rev, nil
}

// updateConnection updates the current gRPC connection and client.
// It also increments the revision and notifies all waiters.
// If there was a previous connection, it is closed.
func (cm *connectionManager) updateConnection(conn *grpc.ClientConn) uint64 {
	cm.connMu.Lock()
	cm.mu.Lock()

	prev := cm.connection

	cm.connection = conn
	if conn != nil {
		cm.fqdnClient = pb.NewFQDNDataClient(conn)
	} else {
		cm.fqdnClient = nil
	}
	cm.revision++

	newRev := cm.revision
	cm.mu.Unlock()
	cm.connCond.Broadcast()
	cm.connMu.Unlock()

	if prev != nil && prev != conn {
		_ = prev.Close()
	}
	cm.emit(connEvent{Connected: conn != nil, Rev: newRev})
	return newRev
}

// Close closes the current gRPC connection and clears the client.
// It also increments the revision and notifies all waiters.
func (cm *connectionManager) Close() error {
	cm.connMu.Lock()
	cm.mu.Lock()
	var err error
	if cm.connection != nil {
		err = cm.connection.Close()
	}
	cm.connection = nil
	cm.fqdnClient = nil
	cm.revision++
	newRev := cm.revision
	cm.mu.Unlock()
	cm.connCond.Broadcast()
	cm.connMu.Unlock()

	cm.emit(connEvent{Connected: false, Rev: newRev})
	return err
}

// isConnected returns true if a gRPC connection is established.
func (cm *connectionManager) isConnected() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.fqdnClient != nil
}

// removeConnection removes the current gRPC connection and client if the revision matches.
// removeConnection is called by the connection consumer to report a connection-level failure.
func (cm *connectionManager) removeConnection(rev uint64) bool {
	cm.connMu.Lock()
	cm.mu.Lock()
	if cm.revision != rev {
		cm.mu.Unlock()
		cm.connMu.Unlock()
		return false
	}
	if cm.connection != nil {
		_ = cm.connection.Close()
	}
	cm.connection = nil
	cm.fqdnClient = nil
	cm.revision++
	newRev := cm.revision
	cm.mu.Unlock()
	cm.connCond.Broadcast()
	cm.connMu.Unlock()

	cm.emit(connEvent{Connected: false, Rev: newRev})
	return true
}
