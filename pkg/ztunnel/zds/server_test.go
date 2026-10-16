// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	apimachineryTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

var (
	zdsTestUnixAddress = "@zds-test-socket"

	testUID = "test-uid"
)

func setupZDSTestSuite(t *testing.T) *Server {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	server := newZDSServer(serverParams{
		Config:      config.Config{EnableZTunnel: true},
		ZDSUnixAddr: zdsTestUnixAddress,
		Lifecycle:   hivetest.Lifecycle(t),
		Logger:      logger,
	})
	require.NotNil(t, server.Server)
	require.NotNil(t, server.Server.l, "server listener should be initialized")

	return server.Server
}

func dialZDSClient(t *testing.T) (net.Conn, *ztunnelConn) {
	t.Helper()

	conn, err := net.Dial("unixpacket", zdsTestUnixAddress)
	require.NoError(t, err)

	uc, ok := conn.(*net.UnixConn)
	require.True(t, ok)

	return conn, &ztunnelConn{conn: uc}
}

func sendHello(t *testing.T, conn net.Conn) {
	t.Helper()

	helloMsg := &pb.ZdsHello{Version: pb.Version_V1}
	data, err := proto.Marshal(helloMsg)
	require.NoError(t, err)
	_, err = conn.Write(data)
	require.NoError(t, err)
}

func expectSnapshotAndAck(t *testing.T, clientZC *ztunnelConn, conn net.Conn, ackErr string) {
	t.Helper()

	req := &pb.WorkloadRequest{}
	err := clientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetSnapshotSent(), "Expected SnapshotSent, got %T", req.Payload)

	ack := &pb.WorkloadResponse{
		Payload: &pb.WorkloadResponse_Ack{
			Ack: &pb.Ack{Error: ackErr},
		},
	}
	ackData, err := proto.Marshal(ack)
	require.NoError(t, err)
	_, err = conn.Write(ackData)
	require.NoError(t, err)
}

func TestPrivilegedZDSConnHandler(t *testing.T) {
	server := setupZDSTestSuite(t)

	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)

	expectSnapshotAndAck(t, clientZC, conn, "")
}

func TestPrivilegedZDSConnHandlerAckError(t *testing.T) {
	server := setupZDSTestSuite(t)

	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)

	// Expect an error in the snapshot ack
	expectSnapshotAndAck(t, clientZC, conn, "client-side error")
}

// createTestEndpoint creates a test endpoint with a real network namespace.
// The namespace will be pinned to a temporary path so it can be used by EnrollEndpoint.
// The caller is responsible for cleaning up the namespace and unpinning it.
func createTestEndpoint(t *testing.T, uid string, id uint16) (*endpoint.Endpoint, func()) {
	t.Helper()

	ns, err := netns.New()
	require.NoError(t, err)

	// Pin the namespace to a temporary path so EnrollEndpoint can open it
	tmpDir := t.TempDir()
	netnsPath := filepath.Join(tmpDir, uid)
	f, err := os.Create(netnsPath)
	require.NoError(t, err)
	f.Close()

	// Bind mount the namespace to pin it
	// This keeps the namespace alive even after ns.Close() is called
	nsFdPath := fmt.Sprintf("/proc/self/fd/%d", ns.FD())
	err = unix.Mount(nsFdPath, netnsPath, "none", unix.MS_BIND, "")
	require.NoError(t, err)

	ns.Close()

	// Create a mock endpoint with Pod information
	ep := &endpoint.Endpoint{
		ID:           id,
		K8sUID:       uid,
		K8sPodName:   "test-pod-" + uid,
		K8sNamespace: "test-namespace",
	}
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      ep.K8sPodName,
			Namespace: ep.K8sNamespace,
			UID:       apimachineryTypes.UID(uid),
		},
		Spec: slim_corev1.PodSpec{
			NodeName:           "test-node",
			ServiceAccountName: "test-service-account",
		},
	}
	ep.SetPod(pod)
	ep.SetContainerNetnsPath(netnsPath)

	cleanup := func() {
		unix.Unmount(netnsPath, unix.MNT_DETACH)
		os.Remove(netnsPath)
	}

	return ep, cleanup
}

func TestPrivilegedZDSConnHandlerEndpointUpdate(t *testing.T) {
	server := setupZDSTestSuite(t)

	// Seed the initial snapshot
	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)

	expectSnapshotAndAck(t, clientZC, conn, "")

	ep, cleanup := createTestEndpoint(t, testUID, 1)
	defer cleanup()

	// Enroll the endpoint in a goroutine to avoid deadlock
	enrollDone := make(chan error, 1)
	go func() {
		enrollDone <- server.EnrollEndpoint(ep)
	}()

	// Read and ACK the enrollment message
	req := &pb.WorkloadRequest{}
	err := clientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
	require.Equal(t, testUID, req.GetAdd().GetUid(), "Expected Add UID %s, got %s", testUID, req.GetAdd().GetUid())

	ack := &pb.WorkloadResponse{
		Payload: &pb.WorkloadResponse_Ack{
			Ack: &pb.Ack{},
		},
	}
	ackData, err := proto.Marshal(ack)
	require.NoError(t, err)
	_, err = conn.Write(ackData)
	require.NoError(t, err)

	// Wait for enrollment to complete
	err = <-enrollDone
	require.NoError(t, err)

	// Disenroll the endpoint in a goroutine
	go func() {
		enrollDone <- server.DisenrollEndpoint(ep)
	}()

	// Read and ACK the disenrollment message
	req = &pb.WorkloadRequest{}
	err = clientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetDel(), "Expected Del, got %T", req.Payload)
	require.Equal(t, testUID, req.GetDel().GetUid(), "Expected Del UID %s, got %s", testUID, req.GetDel().GetUid())

	ackData, err = proto.Marshal(ack)
	require.NoError(t, err)
	_, err = conn.Write(ackData)
	require.NoError(t, err)

	// Wait for disenrollment to complete
	err = <-enrollDone
	require.NoError(t, err)

	// The endpoint should be evicted from the cache after a successful disenroll.
	server.endpointCacheMutex.Lock()
	_, ok := server.endpointCache[ep.GetID16()]
	server.endpointCacheMutex.Unlock()
	require.False(t, ok, "endpoint should be evicted from cache after disenroll")
}

// TestPrivilegedZDSRollingUpdate tests the scenario where a ztunnel pod is rolling updated.
// This simulates the following:
// 1. Old ztunnel connects and receives the current state
// 2. Some workload updates are sent to old ztunnel via EnrollEndpoint, and they're added to the cache
// 3. New ztunnel connects (during rolling update)
// 4. Old ztunnel connection should be cancelled
// 5. New ztunnel should receive full snapshot of current state from cache
// 6. New updates should only go to new ztunnel
func TestPrivilegedZDSRollingUpdate(t *testing.T) {
	server := setupZDSTestSuite(t)

	server.SeedInitialSnapshot()

	// First ztunnel connects (old version)
	oldConn, oldClientZC := dialZDSClient(t)
	defer oldConn.Close()

	sendHello(t, oldConn)
	expectSnapshotAndAck(t, oldClientZC, oldConn, "")

	ep1, cleanup1 := createTestEndpoint(t, "workload-1", 1)
	defer cleanup1()

	// Enroll the first endpoint in a goroutine to avoid deadlock
	// (EnrollEndpoint waits for ACK, but we need to read the message first)
	enrollDone := make(chan error, 1)
	go func() {
		enrollDone <- server.EnrollEndpoint(ep1)
	}()

	// Read and ACK the enrollment message
	req := &pb.WorkloadRequest{}
	err := oldClientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
	require.Equal(t, "workload-1", req.GetAdd().GetUid())

	ack := &pb.WorkloadResponse{
		Payload: &pb.WorkloadResponse_Ack{
			Ack: &pb.Ack{},
		},
	}
	ackData, err := proto.Marshal(ack)
	require.NoError(t, err)
	_, err = oldConn.Write(ackData)
	require.NoError(t, err)

	// Wait for enrollment to complete
	err = <-enrollDone
	require.NoError(t, err)

	ep2, cleanup2 := createTestEndpoint(t, "workload-2", 2)
	defer cleanup2()

	go func() {
		enrollDone <- server.EnrollEndpoint(ep2)
	}()

	err = oldClientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
	require.Equal(t, "workload-2", req.GetAdd().GetUid())

	_, err = oldConn.Write(ackData)
	require.NoError(t, err)

	err = <-enrollDone
	require.NoError(t, err)

	// Now simulate a rolling update: new ztunnel connects
	newConn, newClientZC := dialZDSClient(t)
	defer newConn.Close()

	sendHello(t, newConn)

	// New ztunnel should receive the snapshot which includes BOTH workloads
	// Note: The order may not be deterministic due to map iteration
	receivedUIDs := make(map[string]bool)

	err = newClientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetAdd(), "Expected Add in snapshot, got %T", req.Payload)
	receivedUIDs[req.GetAdd().GetUid()] = true
	_, err = newConn.Write(ackData)
	require.NoError(t, err)

	err = newClientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetAdd(), "Expected Add in snapshot, got %T", req.Payload)
	receivedUIDs[req.GetAdd().GetUid()] = true
	_, err = newConn.Write(ackData)
	require.NoError(t, err)

	// Verify we received both workloads
	require.True(t, receivedUIDs["workload-1"], "Expected to receive workload-1 in snapshot")
	require.True(t, receivedUIDs["workload-2"], "Expected to receive workload-2 in snapshot")

	// Snapshot sent marker
	err = newClientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetSnapshotSent(), "Expected SnapshotSent, got %T", req.Payload)
	_, err = newConn.Write(ackData)
	require.NoError(t, err)

	ep3, cleanup3 := createTestEndpoint(t, "workload-3", 3)
	defer cleanup3()

	go func() {
		enrollDone <- server.EnrollEndpoint(ep3)
	}()

	err = newClientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
	require.Equal(t, "workload-3", req.GetAdd().GetUid())
	_, err = newConn.Write(ackData)
	require.NoError(t, err)

	err = <-enrollDone
	require.NoError(t, err)

	// Old connection should be cancelled and return an error when trying to read
	// Note: the old connection may already be closed by the time we try to read
	// This is expected behavior during a rolling update
	err = oldClientZC.readMsg(req)
	require.Error(t, err)
}

// TestPrivilegedZDSDisenrollMissingNetns verifies that when an endpoint's netns
// is already gone (e.g. CNI DEL ran before disenrollment), disenroll still drops
// the workload from ztunnel and evicts the stale cache entry instead of leaking
// it, which would otherwise abort a later sendInitialSnapshot.
func TestPrivilegedZDSDisenrollMissingNetns(t *testing.T) {
	server := setupZDSTestSuite(t)
	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)
	expectSnapshotAndAck(t, clientZC, conn, "")

	ep, cleanup := createTestEndpoint(t, testUID, 1)
	defer cleanup()

	ack := &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}}
	ackData, err := proto.Marshal(ack)
	require.NoError(t, err)

	// Enroll so the endpoint is in the cache.
	enrollDone := make(chan error, 1)
	go func() { enrollDone <- server.EnrollEndpoint(ep) }()

	req := &pb.WorkloadRequest{}
	require.NoError(t, clientZC.readMsg(req))
	require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
	_, err = conn.Write(ackData)
	require.NoError(t, err)
	require.NoError(t, <-enrollDone)

	// Simulate CNI DEL removing the netns before disenroll: point the endpoint at
	// a netns path that no longer exists so OpenPinned returns ENOENT.
	ep.SetContainerNetnsPath(filepath.Join(t.TempDir(), "missing-netns"))

	disenrollDone := make(chan error, 1)
	go func() { disenrollDone <- server.DisenrollEndpoint(ep) }()

	// ztunnel still receives a Del for the workload.
	req = &pb.WorkloadRequest{}
	require.NoError(t, clientZC.readMsg(req))
	require.NotNil(t, req.GetDel(), "Expected Del, got %T", req.Payload)
	require.Equal(t, testUID, req.GetDel().GetUid())
	_, err = conn.Write(ackData)
	require.NoError(t, err)
	require.NoError(t, <-disenrollDone)

	// The stale entry must be evicted.
	server.endpointCacheMutex.Lock()
	_, ok := server.endpointCache[ep.GetID16()]
	server.endpointCacheMutex.Unlock()
	require.False(t, ok, "endpoint should be evicted from cache when netns is gone")
}

// TestPrivilegedZDSDisenrollNetnsOpenError verifies that a non-ENOENT failure to
// open the netns (e.g. a live pod hitting a transient error) fails closed: the
// endpoint stays enrolled in the cache and no Del is sent to ztunnel.
func TestPrivilegedZDSDisenrollNetnsOpenError(t *testing.T) {
	server := setupZDSTestSuite(t)
	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)
	expectSnapshotAndAck(t, clientZC, conn, "")

	ep, cleanup := createTestEndpoint(t, testUID, 1)
	defer cleanup()

	ack := &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}}
	ackData, err := proto.Marshal(ack)
	require.NoError(t, err)

	enrollDone := make(chan error, 1)
	go func() { enrollDone <- server.EnrollEndpoint(ep) }()

	req := &pb.WorkloadRequest{}
	require.NoError(t, clientZC.readMsg(req))
	require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
	_, err = conn.Write(ackData)
	require.NoError(t, err)
	require.NoError(t, <-enrollDone)

	// Force a non-ENOENT open error: a path whose parent is a regular file yields
	// ENOTDIR, for which os.IsNotExist is false.
	notDir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notDir, nil, 0o600))
	ep.SetContainerNetnsPath(filepath.Join(notDir, "netns"))

	// Disenroll returns the error synchronously, before any Del is sent.
	require.Error(t, server.DisenrollEndpoint(ep))

	// No Del should have been sent to ztunnel.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	require.Error(t, clientZC.readMsg(req), "no Del should be sent on a non-ENOENT netns error")
	require.NoError(t, conn.SetReadDeadline(time.Time{}))

	// The endpoint must remain enrolled (fail closed).
	server.endpointCacheMutex.Lock()
	_, ok := server.endpointCache[ep.GetID16()]
	server.endpointCacheMutex.Unlock()
	require.True(t, ok, "endpoint should remain in cache on a non-ENOENT netns error")
}

// TestPrivilegedZDSSnapshotSkipsMissingNetns verifies that an endpoint whose
// netns is already gone is skipped during the initial snapshot (rather than
// aborting it), so a live endpoint and the SnapshotSent marker are still
// delivered. A stale cache entry must not break the whole snapshot.
func TestPrivilegedZDSSnapshotSkipsMissingNetns(t *testing.T) {
	server := setupZDSTestSuite(t)

	ep1, cleanup1 := createTestEndpoint(t, "live-ep", 1)
	defer cleanup1()
	ep2, cleanup2 := createTestEndpoint(t, "missing-ep", 2)
	defer cleanup2()

	server.SeedInitialSnapshot(ep1, ep2)

	// Make ep2's netns disappear so OpenPinned returns ENOENT during the snapshot.
	ep2.SetContainerNetnsPath(filepath.Join(t.TempDir(), "missing-netns"))

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()
	sendHello(t, conn)

	ack := &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}}
	ackData, err := proto.Marshal(ack)
	require.NoError(t, err)

	// The snapshot should deliver the live endpoint and the SnapshotSent marker,
	// skipping the endpoint whose netns is gone. Map iteration order is not
	// deterministic, so collect by UID until SnapshotSent arrives.
	receivedUIDs := make(map[string]bool)
	for {
		req := &pb.WorkloadRequest{}
		require.NoError(t, clientZC.readMsg(req))
		if req.GetSnapshotSent() != nil {
			_, err = conn.Write(ackData)
			require.NoError(t, err)
			break
		}
		require.NotNil(t, req.GetAdd(), "Expected Add, got %T", req.Payload)
		receivedUIDs[req.GetAdd().GetUid()] = true
		_, err = conn.Write(ackData)
		require.NoError(t, err)
	}

	require.True(t, receivedUIDs["live-ep"], "live endpoint should be in the snapshot")
	require.False(t, receivedUIDs["missing-ep"], "endpoint with missing netns should be skipped")
}

// TestPrivilegedZDSSnapshotAbortsOnNetnsError verifies that a non-ENOENT failure
// to open an endpoint's netns still aborts the initial snapshot (original
// behavior), so the connection is closed without a SnapshotSent marker.
func TestPrivilegedZDSSnapshotAbortsOnNetnsError(t *testing.T) {
	server := setupZDSTestSuite(t)

	ep, cleanup := createTestEndpoint(t, "err-ep", 1)
	defer cleanup()

	server.SeedInitialSnapshot(ep)

	// Force a non-ENOENT open error: a path whose parent is a regular file yields
	// ENOTDIR, for which os.IsNotExist is false.
	notDir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notDir, nil, 0o600))
	ep.SetContainerNetnsPath(filepath.Join(notDir, "netns"))

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()
	sendHello(t, conn)

	// The snapshot aborts before SnapshotSent and the server closes the
	// connection, so the client read fails.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	req := &pb.WorkloadRequest{}
	require.Error(t, clientZC.readMsg(req), "snapshot should abort on a non-ENOENT netns error")
}
