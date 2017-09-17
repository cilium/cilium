package node

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/docker/docker/pkg/plugingetter"
	metrics "github.com/docker/go-metrics"
	"github.com/docker/swarmkit/agent"
	"github.com/docker/swarmkit/agent/exec"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/connectionbroker"
	"github.com/docker/swarmkit/ioutils"
	"github.com/docker/swarmkit/log"
	"github.com/docker/swarmkit/manager"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/docker/swarmkit/remotes"
	"github.com/docker/swarmkit/xnet"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

const (
	stateFilename     = "state.json"
	roleChangeTimeout = 16 * time.Second
)

var (
	nodeInfo    metrics.LabeledGauge
	nodeManager metrics.Gauge

	errNodeStarted    = errors.New("node: already started")
	errNodeNotStarted = errors.New("node: not started")
	certDirectory     = "certificates"

	// ErrInvalidUnlockKey is returned when we can't decrypt the TLS certificate
	ErrInvalidUnlockKey = errors.New("node is locked, and needs a valid unlock key")
)

func init() {
	ns := metrics.NewNamespace("swarm", "node", nil)
	nodeInfo = ns.NewLabeledGauge("info", "Information related to the swarm", "",
		"swarm_id",
		"node_id",
	)
	nodeManager = ns.NewGauge("manager", "Whether this node is a manager or not", "")
	metrics.Register(ns)
}

// Config provides values for a Node.
type Config struct {
	// Hostname is the name of host for agent instance.
	Hostname string

	// JoinAddr specifies node that should be used for the initial connection to
	// other manager in cluster. This should be only one address and optional,
	// the actual remotes come from the stored state.
	JoinAddr string

	// StateDir specifies the directory the node uses to keep the state of the
	// remote managers and certificates.
	StateDir string

	// JoinToken is the token to be used on the first certificate request.
	JoinToken string

	// ExternalCAs is a list of CAs to which a manager node
	// will make certificate signing requests for node certificates.
	ExternalCAs []*api.ExternalCA

	// ForceNewCluster creates a new cluster from current raft state.
	ForceNewCluster bool

	// ListenControlAPI specifies address the control API should listen on.
	ListenControlAPI string

	// ListenRemoteAPI specifies the address for the remote API that agents
	// and raft members connect to.
	ListenRemoteAPI string

	// AdvertiseRemoteAPI specifies the address that should be advertised
	// for connections to the remote API (including the raft service).
	AdvertiseRemoteAPI string

	// Executor specifies the executor to use for the agent.
	Executor exec.Executor

	// ElectionTick defines the amount of ticks needed without
	// leader to trigger a new election
	ElectionTick uint32

	// HeartbeatTick defines the amount of ticks between each
	// heartbeat sent to other members for health-check purposes
	HeartbeatTick uint32

	// AutoLockManagers determines whether or not an unlock key will be generated
	// when bootstrapping a new cluster for the first time
	AutoLockManagers bool

	// UnlockKey is the key to unlock a node - used for decrypting at rest.  This
	// only applies to nodes that have already joined a cluster.
	UnlockKey []byte

	// Availability allows a user to control the current scheduling status of a node
	Availability api.NodeSpec_Availability

	// PluginGetter provides access to docker's plugin inventory.
	PluginGetter plugingetter.PluginGetter
}

// Node implements the primary node functionality for a member of a swarm
// cluster. Node handles workloads and may also run as a manager.
type Node struct {
	sync.RWMutex
	config           *Config
	remotes          *persistentRemotes
	connBroker       *connectionbroker.Broker
	role             string
	roleCond         *sync.Cond
	conn             *grpc.ClientConn
	connCond         *sync.Cond
	nodeID           string
	started          chan struct{}
	startOnce        sync.Once
	stopped          chan struct{}
	stopOnce         sync.Once
	ready            chan struct{} // closed when agent has completed registration and manager(if enabled) is ready to receive control requests
	closed           chan struct{}
	err              error
	agent            *agent.Agent
	manager          *manager.Manager
	notifyNodeChange chan *agent.NodeChanges // used by the agent to relay node updates from the dispatcher Session stream to (*Node).run
	unlockKey        []byte
}

type lastSeenRole struct {
	role api.NodeRole
}

// observe notes the latest value of this node role, and returns true if it
// is the first seen value, or is different from the most recently seen value.
func (l *lastSeenRole) observe(newRole api.NodeRole) bool {
	changed := l.role != newRole
	l.role = newRole
	return changed
}

// RemoteAPIAddr returns address on which remote manager api listens.
// Returns nil if node is not manager.
func (n *Node) RemoteAPIAddr() (string, error) {
	n.RLock()
	defer n.RUnlock()
	if n.manager == nil {
		return "", errors.New("manager is not running")
	}
	addr := n.manager.Addr()
	if addr == "" {
		return "", errors.New("manager addr is not set")
	}
	return addr, nil
}

// New returns new Node instance.
func New(c *Config) (*Node, error) {
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return nil, err
	}
	stateFile := filepath.Join(c.StateDir, stateFilename)
	dt, err := ioutil.ReadFile(stateFile)
	var p []api.Peer
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(dt, &p); err != nil {
			return nil, err
		}
	}
	n := &Node{
		remotes:          newPersistentRemotes(stateFile, p...),
		role:             ca.WorkerRole,
		config:           c,
		started:          make(chan struct{}),
		stopped:          make(chan struct{}),
		closed:           make(chan struct{}),
		ready:            make(chan struct{}),
		notifyNodeChange: make(chan *agent.NodeChanges, 1),
		unlockKey:        c.UnlockKey,
	}

	if n.config.JoinAddr != "" || n.config.ForceNewCluster {
		n.remotes = newPersistentRemotes(filepath.Join(n.config.StateDir, stateFilename))
		if n.config.JoinAddr != "" {
			n.remotes.Observe(api.Peer{Addr: n.config.JoinAddr}, remotes.DefaultObservationWeight)
		}
	}

	n.connBroker = connectionbroker.New(n.remotes)

	n.roleCond = sync.NewCond(n.RLocker())
	n.connCond = sync.NewCond(n.RLocker())
	return n, nil
}

// BindRemote starts a listener that exposes the remote API.
func (n *Node) BindRemote(ctx context.Context, listenAddr string, advertiseAddr string) error {
	n.RLock()
	defer n.RUnlock()

	if n.manager == nil {
		return errors.New("manager is not running")
	}

	return n.manager.BindRemote(ctx, manager.RemoteAddrs{
		ListenAddr:    listenAddr,
		AdvertiseAddr: advertiseAddr,
	})
}

// Start starts a node instance.
func (n *Node) Start(ctx context.Context) error {
	err := errNodeStarted

	n.startOnce.Do(func() {
		close(n.started)
		go n.run(ctx)
		err = nil // clear error above, only once.
	})

	return err
}

func (n *Node) currentRole() api.NodeRole {
	n.Lock()
	currentRole := api.NodeRoleWorker
	if n.role == ca.ManagerRole {
		currentRole = api.NodeRoleManager
	}
	n.Unlock()
	return currentRole
}

func (n *Node) run(ctx context.Context) (err error) {
	defer func() {
		n.err = err
		close(n.closed)
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = log.WithModule(ctx, "node")

	go func(ctx context.Context) {
		select {
		case <-ctx.Done():
		case <-n.stopped:
			cancel()
		}
	}(ctx)

	paths := ca.NewConfigPaths(filepath.Join(n.config.StateDir, certDirectory))
	securityConfig, secConfigCancel, err := n.loadSecurityConfig(ctx, paths)
	if err != nil {
		return err
	}
	defer secConfigCancel()

	renewer := ca.NewTLSRenewer(securityConfig, n.connBroker, paths.RootCA)

	ctx = log.WithLogger(ctx, log.G(ctx).WithField("node.id", n.NodeID()))

	taskDBPath := filepath.Join(n.config.StateDir, "worker", "tasks.db")
	if err := os.MkdirAll(filepath.Dir(taskDBPath), 0777); err != nil {
		return err
	}

	db, err := bolt.Open(taskDBPath, 0666, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	agentDone := make(chan struct{})

	go func() {
		// lastNodeDesiredRole is the last-seen value of Node.Spec.DesiredRole,
		// used to make role changes "edge triggered" and avoid renewal loops.
		lastNodeDesiredRole := lastSeenRole{role: n.currentRole()}

		for {
			select {
			case <-agentDone:
				return
			case nodeChanges := <-n.notifyNodeChange:
				currentRole := n.currentRole()

				if nodeChanges.Node != nil {
					// This is a bit complex to be backward compatible with older CAs that
					// don't support the Node.Role field. They only use what's presently
					// called DesiredRole.
					// 1) If DesiredRole changes, kick off a certificate renewal. The renewal
					//    is delayed slightly to give Role time to change as well if this is
					//    a newer CA. If the certificate we get back doesn't have the expected
					//    role, we continue renewing with exponential backoff.
					// 2) If the server is sending us IssuanceStateRotate, renew the cert as
					//    requested by the CA.
					desiredRoleChanged := lastNodeDesiredRole.observe(nodeChanges.Node.Spec.DesiredRole)
					if desiredRoleChanged {
						switch nodeChanges.Node.Spec.DesiredRole {
						case api.NodeRoleManager:
							renewer.SetExpectedRole(ca.ManagerRole)
						case api.NodeRoleWorker:
							renewer.SetExpectedRole(ca.WorkerRole)
						}
					}
					if desiredRoleChanged || nodeChanges.Node.Certificate.Status.State == api.IssuanceStateRotate {
						renewer.Renew()
					}
				}

				if nodeChanges.RootCert != nil {
					// We only want to update the root CA if this is a worker node.  Manager nodes directly watch the raft
					// store and update the root CA, with the necessary signer, from the raft store (since the managers
					// need the CA key as well to potentially issue new TLS certificates).
					if currentRole == api.NodeRoleManager || bytes.Equal(nodeChanges.RootCert, securityConfig.RootCA().Certs) {
						continue
					}
					newRootCA, err := ca.NewRootCA(nodeChanges.RootCert, nil, nil, ca.DefaultNodeCertExpiration, nil)
					if err != nil {
						log.G(ctx).WithError(err).Error("invalid new root certificate from the dispatcher")
						continue
					}
					if err := securityConfig.UpdateRootCA(&newRootCA, newRootCA.Pool); err != nil {
						log.G(ctx).WithError(err).Error("could not use new root CA from dispatcher")
						continue
					}
					if err := ca.SaveRootCA(newRootCA, paths.RootCA); err != nil {
						log.G(ctx).WithError(err).Error("could not save new root certificate from the dispatcher")
						continue
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(3)

	nodeInfo.WithValues(
		securityConfig.ClientTLSCreds.Organization(),
		securityConfig.ClientTLSCreds.NodeID(),
	).Set(1)

	if n.currentRole() == api.NodeRoleManager {
		nodeManager.Set(1)
	} else {
		nodeManager.Set(0)
	}

	updates := renewer.Start(ctx)
	go func() {
		for certUpdate := range updates {
			if certUpdate.Err != nil {
				logrus.Warnf("error renewing TLS certificate: %v", certUpdate.Err)
				continue
			}
			n.Lock()
			n.role = certUpdate.Role
			n.roleCond.Broadcast()
			n.Unlock()

			// Export the new role.
			if n.currentRole() == api.NodeRoleManager {
				nodeManager.Set(1)
			} else {
				nodeManager.Set(0)
			}
		}

		wg.Done()
	}()

	role := n.role

	managerReady := make(chan struct{})
	agentReady := make(chan struct{})
	var managerErr error
	var agentErr error
	go func() {
		managerErr = n.superviseManager(ctx, securityConfig, paths.RootCA, managerReady, renewer) // store err and loop
		wg.Done()
		cancel()
	}()
	go func() {
		agentErr = n.runAgent(ctx, db, securityConfig, agentReady)
		wg.Done()
		cancel()
		close(agentDone)
	}()

	go func() {
		<-agentReady
		if role == ca.ManagerRole {
			workerRole := make(chan struct{})
			waitRoleCtx, waitRoleCancel := context.WithCancel(ctx)
			go func() {
				if n.waitRole(waitRoleCtx, ca.WorkerRole) == nil {
					close(workerRole)
				}
			}()
			select {
			case <-managerReady:
			case <-workerRole:
			}
			waitRoleCancel()
		}
		close(n.ready)
	}()

	wg.Wait()
	if managerErr != nil && errors.Cause(managerErr) != context.Canceled {
		return managerErr
	}
	if agentErr != nil && errors.Cause(agentErr) != context.Canceled {
		return agentErr
	}
	return err
}

// Stop stops node execution
func (n *Node) Stop(ctx context.Context) error {
	select {
	case <-n.started:
	default:
		return errNodeNotStarted
	}
	// ask agent to clean up assignments
	n.Lock()
	if n.agent != nil {
		if err := n.agent.Leave(ctx); err != nil {
			log.G(ctx).WithError(err).Error("agent failed to clean up assignments")
		}
	}
	n.Unlock()

	n.stopOnce.Do(func() {
		close(n.stopped)
	})

	select {
	case <-n.closed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Err returns the error that caused the node to shutdown or nil. Err blocks
// until the node has fully shut down.
func (n *Node) Err(ctx context.Context) error {
	select {
	case <-n.closed:
		return n.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *Node) runAgent(ctx context.Context, db *bolt.DB, securityConfig *ca.SecurityConfig, ready chan<- struct{}) error {
	waitCtx, waitCancel := context.WithCancel(ctx)
	remotesCh := n.remotes.WaitSelect(ctx)
	controlCh := n.ListenControlSocket(waitCtx)

waitPeer:
	for {
		select {
		case <-ctx.Done():
			break waitPeer
		case <-remotesCh:
			break waitPeer
		case conn := <-controlCh:
			if conn != nil {
				break waitPeer
			}
		}
	}

	waitCancel()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	secChangesCh, secChangesCancel := securityConfig.Watch()
	defer secChangesCancel()

	rootCA := securityConfig.RootCA()
	issuer := securityConfig.IssuerInfo()

	agentConfig := &agent.Config{
		Hostname:         n.config.Hostname,
		ConnBroker:       n.connBroker,
		Executor:         n.config.Executor,
		DB:               db,
		NotifyNodeChange: n.notifyNodeChange,
		NotifyTLSChange:  secChangesCh,
		Credentials:      securityConfig.ClientTLSCreds,
		NodeTLSInfo: &api.NodeTLSInfo{
			TrustRoot:           rootCA.Certs,
			CertIssuerPublicKey: issuer.PublicKey,
			CertIssuerSubject:   issuer.Subject,
		},
	}
	// if a join address has been specified, then if the agent fails to connect due to a TLS error, fail fast - don't
	// keep re-trying to join
	if n.config.JoinAddr != "" {
		agentConfig.SessionTracker = &firstSessionErrorTracker{}
	}

	a, err := agent.New(agentConfig)
	if err != nil {
		return err
	}
	if err := a.Start(ctx); err != nil {
		return err
	}

	n.Lock()
	n.agent = a
	n.Unlock()

	defer func() {
		n.Lock()
		n.agent = nil
		n.Unlock()
	}()

	go func() {
		<-a.Ready()
		close(ready)
	}()

	// todo: manually call stop on context cancellation?

	return a.Err(context.Background())
}

// Ready returns a channel that is closed after node's initialization has
// completes for the first time.
func (n *Node) Ready() <-chan struct{} {
	return n.ready
}

func (n *Node) setControlSocket(conn *grpc.ClientConn) {
	n.Lock()
	if n.conn != nil {
		n.conn.Close()
	}
	n.conn = conn
	n.connBroker.SetLocalConn(conn)
	n.connCond.Broadcast()
	n.Unlock()
}

// ListenControlSocket listens changes of a connection for managing the
// cluster control api
func (n *Node) ListenControlSocket(ctx context.Context) <-chan *grpc.ClientConn {
	c := make(chan *grpc.ClientConn, 1)
	n.RLock()
	conn := n.conn
	c <- conn
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			n.connCond.Broadcast()
		case <-done:
		}
	}()
	go func() {
		defer close(c)
		defer close(done)
		defer n.RUnlock()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if conn == n.conn {
				n.connCond.Wait()
				continue
			}
			conn = n.conn
			select {
			case c <- conn:
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

// NodeID returns current node's ID. May be empty if not set.
func (n *Node) NodeID() string {
	n.RLock()
	defer n.RUnlock()
	return n.nodeID
}

// Manager returns manager instance started by node. May be nil.
func (n *Node) Manager() *manager.Manager {
	n.RLock()
	defer n.RUnlock()
	return n.manager
}

// Agent returns agent instance started by node. May be nil.
func (n *Node) Agent() *agent.Agent {
	n.RLock()
	defer n.RUnlock()
	return n.agent
}

// IsStateDirty returns true if any objects have been added to raft which make
// the state "dirty". Currently, the existence of any object other than the
// default cluster or the local node implies a dirty state.
func (n *Node) IsStateDirty() (bool, error) {
	n.RLock()
	defer n.RUnlock()

	if n.manager == nil {
		return false, errors.New("node is not a manager")
	}

	return n.manager.IsStateDirty()
}

// Remotes returns a list of known peers known to node.
func (n *Node) Remotes() []api.Peer {
	weights := n.remotes.Weights()
	remotes := make([]api.Peer, 0, len(weights))
	for p := range weights {
		remotes = append(remotes, p)
	}
	return remotes
}

func (n *Node) loadSecurityConfig(ctx context.Context, paths *ca.SecurityConfigPaths) (*ca.SecurityConfig, func() error, error) {
	var (
		securityConfig *ca.SecurityConfig
		cancel         func() error
	)

	krw := ca.NewKeyReadWriter(paths.Node, n.unlockKey, &manager.RaftDEKData{})
	if err := krw.Migrate(); err != nil {
		return nil, nil, err
	}

	// Check if we already have a valid certificates on disk.
	rootCA, err := ca.GetLocalRootCA(paths.RootCA)
	if err != nil && err != ca.ErrNoLocalRootCA {
		return nil, nil, err
	}
	if err == nil {
		// if forcing a new cluster, we allow the certificates to be expired - a new set will be generated
		securityConfig, cancel, err = ca.LoadSecurityConfig(ctx, rootCA, krw, n.config.ForceNewCluster)
		if err != nil {
			_, isInvalidKEK := errors.Cause(err).(ca.ErrInvalidKEK)
			if isInvalidKEK {
				return nil, nil, ErrInvalidUnlockKey
			} else if !os.IsNotExist(err) {
				return nil, nil, errors.Wrapf(err, "error while loading TLS certificate in %s", paths.Node.Cert)
			}
		}
	}

	if securityConfig == nil {
		if n.config.JoinAddr == "" {
			// if we're not joining a cluster, bootstrap a new one - and we have to set the unlock key
			n.unlockKey = nil
			if n.config.AutoLockManagers {
				n.unlockKey = encryption.GenerateSecretKey()
			}
			krw = ca.NewKeyReadWriter(paths.Node, n.unlockKey, &manager.RaftDEKData{})
			rootCA, err = ca.CreateRootCA(ca.DefaultRootCN)
			if err != nil {
				return nil, nil, err
			}
			if err := ca.SaveRootCA(rootCA, paths.RootCA); err != nil {
				return nil, nil, err
			}
			log.G(ctx).Debug("generated CA key and certificate")
		} else if err == ca.ErrNoLocalRootCA { // from previous error loading the root CA from disk
			rootCA, err = ca.DownloadRootCA(ctx, paths.RootCA, n.config.JoinToken, n.connBroker)
			if err != nil {
				return nil, nil, err
			}
			log.G(ctx).Debug("downloaded CA certificate")
		}

		// Obtain new certs and setup TLS certificates renewal for this node:
		// - If certificates weren't present on disk, we call CreateSecurityConfig, which blocks
		//   until a valid certificate has been issued.
		// - We wait for CreateSecurityConfig to finish since we need a certificate to operate.

		// Attempt to load certificate from disk
		securityConfig, cancel, err = ca.LoadSecurityConfig(ctx, rootCA, krw, n.config.ForceNewCluster)
		if err == nil {
			log.G(ctx).WithFields(logrus.Fields{
				"node.id": securityConfig.ClientTLSCreds.NodeID(),
			}).Debugf("loaded TLS certificate")
		} else {
			if _, ok := errors.Cause(err).(ca.ErrInvalidKEK); ok {
				return nil, nil, ErrInvalidUnlockKey
			}
			log.G(ctx).WithError(err).Debugf("no node credentials found in: %s", krw.Target())

			securityConfig, cancel, err = rootCA.CreateSecurityConfig(ctx, krw, ca.CertificateRequestConfig{
				Token:        n.config.JoinToken,
				Availability: n.config.Availability,
				ConnBroker:   n.connBroker,
			})

			if err != nil {
				return nil, nil, err
			}
		}
	}

	n.Lock()
	n.role = securityConfig.ClientTLSCreds.Role()
	n.nodeID = securityConfig.ClientTLSCreds.NodeID()
	n.roleCond.Broadcast()
	n.Unlock()

	return securityConfig, cancel, nil
}

func (n *Node) initManagerConnection(ctx context.Context, ready chan<- struct{}) error {
	opts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(grpc_prometheus.UnaryClientInterceptor),
		grpc.WithStreamInterceptor(grpc_prometheus.StreamClientInterceptor),
	}
	insecureCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	opts = append(opts, grpc.WithTransportCredentials(insecureCreds))
	addr := n.config.ListenControlAPI
	opts = append(opts, grpc.WithDialer(
		func(addr string, timeout time.Duration) (net.Conn, error) {
			return xnet.DialTimeoutLocal(addr, timeout)
		}))
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return err
	}
	client := api.NewHealthClient(conn)
	for {
		resp, err := client.Check(ctx, &api.HealthCheckRequest{Service: "ControlAPI"})
		if err != nil {
			return err
		}
		if resp.Status == api.HealthCheckResponse_SERVING {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	n.setControlSocket(conn)
	if ready != nil {
		close(ready)
	}
	return nil
}

func (n *Node) waitRole(ctx context.Context, role string) error {
	n.roleCond.L.Lock()
	if role == n.role {
		n.roleCond.L.Unlock()
		return nil
	}
	finishCh := make(chan struct{})
	defer close(finishCh)
	go func() {
		select {
		case <-finishCh:
		case <-ctx.Done():
			// call broadcast to shutdown this function
			n.roleCond.Broadcast()
		}
	}()
	defer n.roleCond.L.Unlock()
	for role != n.role {
		n.roleCond.Wait()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	return nil
}

func (n *Node) runManager(ctx context.Context, securityConfig *ca.SecurityConfig, rootPaths ca.CertPaths, ready chan struct{}, workerRole <-chan struct{}) (bool, error) {
	var remoteAPI *manager.RemoteAddrs
	if n.config.ListenRemoteAPI != "" {
		remoteAPI = &manager.RemoteAddrs{
			ListenAddr:    n.config.ListenRemoteAPI,
			AdvertiseAddr: n.config.AdvertiseRemoteAPI,
		}
	}

	remoteAddr, _ := n.remotes.Select(n.NodeID())
	m, err := manager.New(&manager.Config{
		ForceNewCluster:  n.config.ForceNewCluster,
		RemoteAPI:        remoteAPI,
		ControlAPI:       n.config.ListenControlAPI,
		SecurityConfig:   securityConfig,
		ExternalCAs:      n.config.ExternalCAs,
		JoinRaft:         remoteAddr.Addr,
		StateDir:         n.config.StateDir,
		HeartbeatTick:    n.config.HeartbeatTick,
		ElectionTick:     n.config.ElectionTick,
		AutoLockManagers: n.config.AutoLockManagers,
		UnlockKey:        n.unlockKey,
		Availability:     n.config.Availability,
		PluginGetter:     n.config.PluginGetter,
		RootCAPaths:      rootPaths,
	})
	if err != nil {
		return false, err
	}
	done := make(chan struct{})
	var runErr error
	go func(logger *logrus.Entry) {
		if err := m.Run(log.WithLogger(context.Background(), logger)); err != nil {
			runErr = err
		}
		close(done)
	}(log.G(ctx))

	var clearData bool
	defer func() {
		n.Lock()
		n.manager = nil
		n.Unlock()
		m.Stop(ctx, clearData)
		<-done
		n.setControlSocket(nil)
	}()

	n.Lock()
	n.manager = m
	n.Unlock()

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	go n.initManagerConnection(connCtx, ready)

	// wait for manager stop or for role change
	select {
	case <-done:
		return false, runErr
	case <-workerRole:
		log.G(ctx).Info("role changed to worker, stopping manager")
		clearData = true
	case <-m.RemovedFromRaft():
		log.G(ctx).Info("manager removed from raft cluster, stopping manager")
		clearData = true
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return clearData, nil
}

func (n *Node) superviseManager(ctx context.Context, securityConfig *ca.SecurityConfig, rootPaths ca.CertPaths, ready chan struct{}, renewer *ca.TLSRenewer) error {
	for {
		if err := n.waitRole(ctx, ca.ManagerRole); err != nil {
			return err
		}

		workerRole := make(chan struct{})
		waitRoleCtx, waitRoleCancel := context.WithCancel(ctx)
		go func() {
			if n.waitRole(waitRoleCtx, ca.WorkerRole) == nil {
				close(workerRole)
			}
		}()

		wasRemoved, err := n.runManager(ctx, securityConfig, rootPaths, ready, workerRole)
		if err != nil {
			waitRoleCancel()
			return errors.Wrap(err, "manager stopped")
		}

		// If the manager stopped running and our role is still
		// "manager", it's possible that the manager was demoted and
		// the agent hasn't realized this yet. We should wait for the
		// role to change instead of restarting the manager immediately.
		err = func() error {
			timer := time.NewTimer(roleChangeTimeout)
			defer timer.Stop()
			defer waitRoleCancel()

			select {
			case <-timer.C:
			case <-workerRole:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}

			if !wasRemoved {
				log.G(ctx).Warn("failed to get worker role after manager stop, restarting manager")
				return nil
			}
			// We need to be extra careful about restarting the
			// manager. It may cause the node to wrongly join under
			// a new Raft ID. Since we didn't see a role change
			// yet, force a certificate renewal. If the certificate
			// comes back with a worker role, we know we shouldn't
			// restart the manager. However, if we don't see
			// workerRole get closed, it means we didn't switch to
			// a worker certificate, either because we couldn't
			// contact a working CA, or because we've been
			// re-promoted. In this case, we must assume we were
			// re-promoted, and restart the manager.
			log.G(ctx).Warn("failed to get worker role after manager stop, forcing certificate renewal")
			timer.Reset(roleChangeTimeout)

			renewer.Renew()

			// Now that the renewal request has been sent to the
			// renewal goroutine, wait for a change in role.
			select {
			case <-timer.C:
				log.G(ctx).Warn("failed to get worker role after manager stop, restarting manager")
			case <-workerRole:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}()
		if err != nil {
			return err
		}

		ready = nil
	}
}

type persistentRemotes struct {
	sync.RWMutex
	c *sync.Cond
	remotes.Remotes
	storePath      string
	lastSavedState []api.Peer
}

func newPersistentRemotes(f string, peers ...api.Peer) *persistentRemotes {
	pr := &persistentRemotes{
		storePath: f,
		Remotes:   remotes.NewRemotes(peers...),
	}
	pr.c = sync.NewCond(pr.RLocker())
	return pr
}

func (s *persistentRemotes) Observe(peer api.Peer, weight int) {
	s.Lock()
	defer s.Unlock()
	s.Remotes.Observe(peer, weight)
	s.c.Broadcast()
	if err := s.save(); err != nil {
		logrus.Errorf("error writing cluster state file: %v", err)
		return
	}
	return
}
func (s *persistentRemotes) Remove(peers ...api.Peer) {
	s.Lock()
	defer s.Unlock()
	s.Remotes.Remove(peers...)
	if err := s.save(); err != nil {
		logrus.Errorf("error writing cluster state file: %v", err)
		return
	}
	return
}

func (s *persistentRemotes) save() error {
	weights := s.Weights()
	remotes := make([]api.Peer, 0, len(weights))
	for r := range weights {
		remotes = append(remotes, r)
	}
	sort.Sort(sortablePeers(remotes))
	if reflect.DeepEqual(remotes, s.lastSavedState) {
		return nil
	}
	dt, err := json.Marshal(remotes)
	if err != nil {
		return err
	}
	s.lastSavedState = remotes
	return ioutils.AtomicWriteFile(s.storePath, dt, 0600)
}

// WaitSelect waits until at least one remote becomes available and then selects one.
func (s *persistentRemotes) WaitSelect(ctx context.Context) <-chan api.Peer {
	c := make(chan api.Peer, 1)
	s.RLock()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.c.Broadcast()
		case <-done:
		}
	}()
	go func() {
		defer s.RUnlock()
		defer close(c)
		defer close(done)
		for {
			if ctx.Err() != nil {
				return
			}
			p, err := s.Select()
			if err == nil {
				c <- p
				return
			}
			s.c.Wait()
		}
	}()
	return c
}

// sortablePeers is a sort wrapper for []api.Peer
type sortablePeers []api.Peer

func (sp sortablePeers) Less(i, j int) bool { return sp[i].NodeID < sp[j].NodeID }

func (sp sortablePeers) Len() int { return len(sp) }

func (sp sortablePeers) Swap(i, j int) { sp[i], sp[j] = sp[j], sp[i] }

// firstSessionErrorTracker is a utility that helps determine whether the agent should exit after
// a TLS failure on establishing the first session.  This should only happen if a join address
// is specified.  If establishing the first session succeeds, but later on some session fails
// because of a TLS error, we don't want to exit the agent because a previously successful
// session indicates that the TLS error may be a transient issue.
type firstSessionErrorTracker struct {
	mu               sync.Mutex
	pastFirstSession bool
	err              error
}

func (fs *firstSessionErrorTracker) SessionEstablished() {
	fs.mu.Lock()
	fs.pastFirstSession = true
	fs.mu.Unlock()
}

func (fs *firstSessionErrorTracker) SessionError(err error) {
	fs.mu.Lock()
	fs.err = err
	fs.mu.Unlock()
}

func (fs *firstSessionErrorTracker) SessionClosed() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	// unfortunately grpc connection errors are type grpc.rpcError, which are not exposed, and we can't get at the underlying error type
	if !fs.pastFirstSession && grpc.Code(fs.err) == codes.Internal &&
		strings.HasPrefix(grpc.ErrorDesc(fs.err), "connection error") && strings.Contains(grpc.ErrorDesc(fs.err), "transport: x509:") {
		return fs.err
	}
	return nil
}
