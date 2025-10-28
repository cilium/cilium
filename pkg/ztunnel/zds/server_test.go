// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

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

	// Create the server instance. The hivetest lifecycle will start it automatically.
	server := newZDSServer(serverParams{
		Config:    config.Config{ZDSUnixAddr: zdsTestUnixAddress},
		Lifecycle: hivetest.Lifecycle(t),
		Logger:    logger,
	})
	require.NotNil(t, server.Server)
	require.NotNil(t, server.Server.l, "server listener should be initialized")

	return server.Server
}

func newAddUpdateRequest(uid string) zdsUpdate {
	return zdsUpdate{
		request: &pb.WorkloadRequest{
			Payload: &pb.WorkloadRequest_Add{
				Add: &pb.AddWorkload{
					WorkloadInfo: &pb.WorkloadInfo{
						Namespace:      "test",
						Name:           "test-pod",
						ServiceAccount: "test-sa",
					},
					Uid: uid,
				},
			},
		},
		ns: nil,
	}
}

func newDelUpdateRequest(uid string) zdsUpdate {
	return zdsUpdate{
		request: &pb.WorkloadRequest{
			Payload: &pb.WorkloadRequest_Del{
				Del: &pb.DelWorkload{
					Uid: uid,
				},
			},
		},
		ns: nil,
	}
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

	// Seed the initial snapshot
	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)

	expectSnapshotAndAck(t, clientZC, conn, "")
}

func TestPrivilegedZDSConnHandlerAckError(t *testing.T) {
	server := setupZDSTestSuite(t)

	// Seed the initial snapshot
	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)

	// Expect an error in the snapshot ack
	expectSnapshotAndAck(t, clientZC, conn, "client-side error")
}

func TestPrivilegedZDSConnHandlerEndpointUpdate(t *testing.T) {
	server := setupZDSTestSuite(t)

	// Seed the initial snapshot
	server.SeedInitialSnapshot()

	conn, clientZC := dialZDSClient(t)
	defer conn.Close()

	sendHello(t, conn)

	expectSnapshotAndAck(t, clientZC, conn, "")

	addUpdate := newAddUpdateRequest(testUID)
	server.updates <- addUpdate
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

	delUpdate := newDelUpdateRequest(testUID)
	server.updates <- delUpdate
	req = &pb.WorkloadRequest{}
	err = clientZC.readMsg(req)
	require.NoError(t, err)
	require.NotNil(t, req.GetDel(), "Expected Del, got %T", req.Payload)
	require.Equal(t, testUID, req.GetDel().GetUid(), "Expected Del UID %s, got %s", testUID, req.GetDel().GetUid())

	ackData, err = proto.Marshal(ack)
	require.NoError(t, err)
	_, err = conn.Write(ackData)
	require.NoError(t, err)
}
