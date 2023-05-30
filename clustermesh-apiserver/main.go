// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	apiserverK8s "github.com/cilium/cilium/clustermesh-apiserver/k8s"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	apiserverOption "github.com/cilium/cilium/clustermesh-apiserver/option"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/heartbeat"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/promise"
)

type configuration struct {
	clusterName             string
	clusterID               uint32
	serviceProxyName        string
	enableExternalWorkloads bool
}

func (c configuration) LocalClusterName() string {
	return c.clusterName
}

func (c configuration) LocalClusterID() uint32 {
	return c.clusterID
}

func (c configuration) K8sServiceProxyNameValue() string {
	return c.serviceProxyName
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "clustermesh-apiserver")

	vp       *viper.Viper
	rootHive *hive.Hive

	rootCmd = &cobra.Command{
		Use:   "clustermesh-apiserver",
		Short: "Run the ClusterMesh apiserver",
		Run: func(cmd *cobra.Command, args []string) {
			if err := rootHive.Run(); err != nil {
				log.Fatal(err)
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for the ClusterMesh API Server
			metrics.Namespace = metrics.CiliumClusterMeshAPIServerNamespace
			option.Config.Populate(vp)
			if option.Config.Debug {
				log.Logger.SetLevel(logrus.DebugLevel)
			}
			option.LogRegisteredOptions(vp, log)
		},
	}

	mockFile string
	cfg      configuration

	ciliumNodeStore *store.SharedStore

	identityStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	// Holds the backend retrieved from the promise. This global variable is used
	// temporarily while the refactoring of the clustermesh-apiserver is in progress
	// to reduce the amount of modifications required in this first step.
	backend kvstore.BackendOperations
)

func init() {
	rootHive = hive.New(
		pprof.Cell,
		cell.Config(pprof.Config{
			PprofAddress: apiserverOption.PprofAddressAPIServer,
			PprofPort:    apiserverOption.PprofPortAPIServer,
		}),

		gops.Cell(defaults.GopsPortApiserver),
		k8sClient.Cell,
		apiserverK8s.ResourcesCell,

		kvstore.Cell(kvstore.EtcdBackendName),
		cell.Provide(func() *kvstore.ExtraOptions { return nil }),
		heartbeat.Cell,

		healthAPIServerCell,
		cmmetrics.Cell,
		usersManagementCell,

		cell.Invoke(registerHooks),
	)
	rootHive.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(rootHive.Command())
	vp = rootHive.Viper()
}

type parameters struct {
	cell.In

	Clientset      k8sClient.Clientset
	Services       resource.Resource[*slim_corev1.Service]
	BackendPromise promise.Promise[kvstore.BackendOperations]
}

func registerHooks(lc hive.Lifecycle, params parameters) error {
	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			if !params.Clientset.IsEnabled() {
				return errors.New("Kubernetes client not configured, cannot continue.")
			}

			var err error
			backend, err = params.BackendPromise.Await(ctx)
			if err != nil {
				return err
			}

			startServer(ctx, params.Clientset, params.Services)
			return nil
		},
	})
	return nil
}

func readMockFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file %s: %s", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.Contains(line, "\"CiliumIdentity\""):
			var identity ciliumv2.CiliumIdentity
			err := json.Unmarshal([]byte(line), &identity)
			if err != nil {
				log.WithError(err).WithField("line", line).Warning("Unable to unmarshal CiliumIdentity")
			} else {
				updateIdentity(&identity)
			}
		case strings.Contains(line, "\"CiliumNode\""):
			var node ciliumv2.CiliumNode
			err = json.Unmarshal([]byte(line), &node)
			if err != nil {
				log.WithError(err).WithField("line", line).Warning("Unable to unmarshal CiliumNode")
			} else {
				updateNode(&node)
			}
		case strings.Contains(line, "\"CiliumEndpoint\""):
			var endpoint types.CiliumEndpoint
			err = json.Unmarshal([]byte(line), &endpoint)
			if err != nil {
				log.WithError(err).WithField("line", line).Warning("Unable to unmarshal CiliumEndpoint")
			} else {
				updateEndpoint(nil, &endpoint)
			}
		case strings.Contains(line, "\"Service\""):
			var service slim_corev1.Service
			err = json.Unmarshal([]byte(line), &service)
			if err != nil {
				log.WithError(err).WithField("line", line).Warning("Unable to unmarshal Service")
			} else {
				operatorWatchers.K8sSvcCache.UpdateService(&service, nil)
			}
		case strings.Contains(line, "\"Endpoints\""):
			var endpoints slim_corev1.Endpoints
			err = json.Unmarshal([]byte(line), &endpoints)
			if err != nil {
				log.WithError(err).WithField("line", line).Warning("Unable to unmarshal Endpoints")
			} else {
				operatorWatchers.K8sSvcCache.UpdateEndpoints(&endpoints, nil)
			}
		default:
			log.Warningf("Unknown line in mockfile %s: %s", path, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func runApiserver() error {
	flags := rootCmd.Flags()
	flags.BoolP(option.DebugArg, "D", false, "Enable debugging mode")
	option.BindEnv(vp, option.DebugArg)

	flags.Duration(option.CRDWaitTimeout, 5*time.Minute, "Cilium will exit if CRDs are not available within this duration upon startup")
	option.BindEnv(vp, option.CRDWaitTimeout)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeCRD, "Method to use for identity allocation")
	option.BindEnv(vp, option.IdentityAllocationMode)

	flags.Uint32Var(&cfg.clusterID, option.ClusterIDName, 0, "Cluster ID")
	option.BindEnv(vp, option.ClusterIDName)

	flags.StringVar(&cfg.clusterName, option.ClusterName, "default", "Cluster name")
	option.BindEnv(vp, option.ClusterName)

	flags.StringVar(&mockFile, "mock-file", "", "Read from mock file")

	flags.StringVar(&cfg.serviceProxyName, option.K8sServiceProxyName, "", "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
	option.BindEnv(vp, option.K8sServiceProxyName)

	flags.Duration(option.AllocatorListTimeoutName, defaults.AllocatorListTimeout, "Timeout for listing allocator state before exiting")
	option.BindEnv(vp, option.AllocatorListTimeoutName)

	flags.Bool(option.EnableWellKnownIdentities, defaults.EnableWellKnownIdentities, "Enable well-known identities for known Kubernetes components")
	option.BindEnv(vp, option.EnableWellKnownIdentities)

	flags.Bool(option.K8sEnableEndpointSlice, defaults.K8sEnableEndpointSlice, "Enable support of Kubernetes EndpointSlice")
	option.BindEnv(vp, option.K8sEnableEndpointSlice)

	// The default values is set to true to match the existing behavior in case
	// the flag is not configured (for instance by the legacy cilium CLI).
	flags.BoolVar(&cfg.enableExternalWorkloads, option.EnableExternalWorkloads, true, "Enable support for external workloads")
	option.BindEnv(vp, option.EnableExternalWorkloads)

	vp.BindPFlags(flags)

	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := runApiserver(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func parseLabelArrayFromMap(base map[string]string) labels.LabelArray {
	array := make(labels.LabelArray, 0, len(base))
	for sourceAndKey, value := range base {
		array = append(array, labels.NewLabel(sourceAndKey, value, ""))
	}
	return array.Sort()
}

func updateIdentity(obj interface{}) {
	identity, ok := obj.(*ciliumv2.CiliumIdentity)
	if !ok {
		log.Warningf("Unknown CiliumIdentity object type %s received: %+v", reflect.TypeOf(obj), obj)
		return
	}

	if identity == nil || identity.SecurityLabels == nil {
		log.Warningf("Ignoring invalid identity %+v", identity)
		return
	}

	keyPath := path.Join(identityCache.IdentitiesPath, "id", identity.Name)
	labelArray := parseLabelArrayFromMap(identity.SecurityLabels)

	var key []byte
	for _, l := range labelArray {
		key = append(key, l.FormatForKVStore()...)
	}

	if len(key) == 0 {
		return
	}

	keyEncoded := []byte(backend.Encode(key))
	log.WithFields(logrus.Fields{"key": keyPath, "value": string(keyEncoded)}).Info("Updating identity in etcd")

	_, err := backend.UpdateIfDifferent(context.Background(), keyPath, keyEncoded, true)
	if err != nil {
		log.WithError(err).Warningf("Unable to update identity %s in etcd", keyPath)
	}
}

func deleteIdentity(obj interface{}) {
	identity, ok := obj.(*ciliumv2.CiliumIdentity)
	if !ok {
		log.Warningf("Unknown CiliumIdentity object type %s received: %+v", reflect.TypeOf(obj), obj)
		return
	}

	if identity == nil {
		log.Warningf("Igoring invalid identity %+v", identity)
		return
	}

	keyPath := path.Join(identityCache.IdentitiesPath, "id", identity.Name)
	err := backend.Delete(context.Background(), keyPath)
	if err != nil {
		log.WithError(err).Warningf("Unable to delete identity %s in etcd", keyPath)
	}
}

func synchronizeIdentities(clientset k8sClient.Clientset) {
	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(clientset.CiliumV2().RESTClient(),
			"ciliumidentities", k8sv1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumIdentity{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: updateIdentity,
			UpdateFunc: func(oldObj, newObj interface{}) {
				updateIdentity(newObj)
			},
			DeleteFunc: func(obj interface{}) {
				deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					deleteIdentity(deletedObj.Obj)
				} else {
					deleteIdentity(obj)
				}
			},
		},
		nil,
		identityStore,
	)

	go identityInformer.Run(wait.NeverStop)
}

type nodeStub struct {
	cluster string
	name    string
}

func (n *nodeStub) GetKeyName() string {
	return nodeTypes.GetKeyNodeName(n.cluster, n.name)
}

func updateNode(obj interface{}) {
	if ciliumNode, ok := obj.(*ciliumv2.CiliumNode); ok {
		n := nodeTypes.ParseCiliumNode(ciliumNode)
		n.Cluster = cfg.clusterName
		n.ClusterID = cfg.clusterID
		if err := ciliumNodeStore.UpdateLocalKeySync(context.Background(), &n); err != nil {
			log.WithError(err).Warning("Unable to insert node into etcd")
		} else {
			log.Infof("Inserted node into etcd: %v", n)
		}
	} else {
		log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
	}
}

func deleteNode(obj interface{}) {
	n, ok := obj.(*ciliumv2.CiliumNode)
	if ok {
		n := nodeStub{
			cluster: cfg.clusterName,
			name:    n.Name,
		}
		ciliumNodeStore.DeleteLocalKey(context.Background(), &n)
	} else {
		log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
	}
}

func synchronizeNodes(clientset k8sClient.Clientset) {
	_, ciliumNodeInformer := informer.NewInformer(
		cache.NewListWatchFromClient(clientset.CiliumV2().RESTClient(),
			"ciliumnodes", k8sv1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: updateNode,
			UpdateFunc: func(_, newObj interface{}) {
				updateNode(newObj)
			},
			DeleteFunc: func(obj interface{}) {
				deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					deleteNode(deletedObj.Obj)
				} else {
					deleteNode(obj)
				}
			},
		},
		k8s.ConvertToCiliumNode,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)
}

func updateEndpoint(oldEp, newEp *types.CiliumEndpoint) {
	var ipsAdded []string
	if n := newEp.Networking; n != nil {
		for _, address := range n.Addressing {
			for _, ip := range []string{address.IPV4, address.IPV6} {
				if ip == "" {
					continue
				}

				keyPath := path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, ip)
				entry := identity.IPIdentityPair{
					IP:           net.ParseIP(ip),
					Metadata:     "",
					HostIP:       net.ParseIP(n.NodeIP),
					K8sNamespace: newEp.Namespace,
					K8sPodName:   newEp.Name,
				}

				if newEp.Identity != nil {
					entry.ID = identity.NumericIdentity(newEp.Identity.ID)
				}

				if newEp.Encryption != nil {
					entry.Key = uint8(newEp.Encryption.Key)
				}

				marshaledEntry, err := json.Marshal(entry)
				if err != nil {
					log.WithError(err).Warningf("Unable to JSON marshal entry %#v", entry)
					continue
				}

				_, err = backend.UpdateIfDifferent(context.Background(), keyPath, marshaledEntry, true)
				if err != nil {
					log.WithError(err).Warningf("Unable to update endpoint %s in etcd", keyPath)
				} else {
					ipsAdded = append(ipsAdded, ip)
					log.Infof("Inserted endpoint into etcd: %v", entry)
				}
			}
		}
	}

	// Delete the old endpoint IPs from the KVStore in case the endpoint
	// changed its IP addresses.
	if oldEp == nil {
		return
	}
	oldNet := oldEp.Networking
	if oldNet == nil {
		return
	}
	for _, address := range oldNet.Addressing {
		for _, oldIP := range []string{address.IPV4, address.IPV6} {
			var found bool
			for _, newIP := range ipsAdded {
				if newIP == oldIP {
					found = true
					break
				}
			}
			if !found {
				// Delete the old IPs from the kvstore:
				keyPath := path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, oldIP)
				if err := backend.Delete(context.Background(), keyPath); err != nil {
					log.WithError(err).
						WithFields(logrus.Fields{
							"path": keyPath,
						}).Warningf("Unable to delete endpoint in etcd")
				}
			}
		}
	}
}

func deleteEndpoint(obj interface{}) {
	e, ok := obj.(*types.CiliumEndpoint)
	if !ok {
		log.Warningf("Unknown CiliumEndpoint object type %T received: %+v", obj, obj)
		return
	}

	if n := e.Networking; n != nil {
		for _, address := range n.Addressing {
			for _, ip := range []string{address.IPV4, address.IPV6} {
				if ip == "" {
					continue
				}

				keyPath := path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, ip)
				if err := backend.Delete(context.Background(), keyPath); err != nil {
					log.WithError(err).Warningf("Unable to delete endpoint %s in etcd", keyPath)
				}
			}
		}
	}
}

func synchronizeCiliumEndpoints(clientset k8sClient.Clientset) {
	_, ciliumEndpointsInformer := informer.NewInformer(
		cache.NewListWatchFromClient(clientset.CiliumV2().RESTClient(),
			"ciliumendpoints", k8sv1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumEndpoint{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				e, ok := obj.(*types.CiliumEndpoint)
				if !ok {
					log.Warningf("Unknown CiliumEndpoint object type %T received: %+v", obj, obj)
					return
				}
				updateEndpoint(nil, e)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldEp, ok := oldObj.(*types.CiliumEndpoint)
				if !ok {
					log.Warningf("Unknown CiliumEndpoint object type %T received: %+v", oldObj, oldObj)
					return
				}
				newEp, ok := newObj.(*types.CiliumEndpoint)
				if !ok {
					log.Warningf("Unknown CiliumEndpoint object type %T received: %+v", newObj, newObj)
					return
				}
				updateEndpoint(oldEp, newEp)
			},
			DeleteFunc: func(obj interface{}) {
				deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					deleteEndpoint(deletedObj.Obj)
				} else {
					deleteEndpoint(obj)
				}
			},
		},
		k8s.ConvertToCiliumEndpoint,
	)

	go ciliumEndpointsInformer.Run(wait.NeverStop)
}

func startServer(startCtx hive.HookContext, clientset k8sClient.Clientset, services resource.Resource[*slim_corev1.Service]) {
	log.WithFields(logrus.Fields{
		"cluster-name": cfg.clusterName,
		"cluster-id":   cfg.clusterID,
	}).Info("Starting clustermesh-apiserver...")

	if mockFile == "" {
		synced.SyncCRDs(startCtx, clientset, synced.AllCiliumCRDResourceNames(), &synced.Resources{}, &synced.APIGroups{})
	}

	var err error

	config := cmtypes.CiliumClusterConfig{
		ID: cfg.clusterID,
	}

	if err := clustermesh.SetClusterConfig(context.Background(), cfg.clusterName, &config, backend); err != nil {
		log.WithError(err).Fatal("Unable to set local cluster config on kvstore")
	}

	if cfg.enableExternalWorkloads {
		mgr := NewVMManager(clientset, backend)
		_, err = store.JoinSharedStore(store.Configuration{
			Backend:              backend,
			Prefix:               nodeStore.NodeRegisterStorePrefix,
			KeyCreator:           nodeStore.RegisterKeyCreator,
			SharedKeyDeleteDelay: defaults.NodeDeleteDelay,
			Observer:             mgr,
		})
		if err != nil {
			log.WithError(err).Fatal("Unable to set up node register store in etcd")
		}
	}

	ciliumNodeStore, err = store.JoinSharedStore(store.Configuration{
		Backend:    backend,
		Prefix:     nodeStore.NodeStorePrefix,
		KeyCreator: nodeStore.KeyCreator,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to set up node store in etcd")
	}

	if mockFile != "" {
		if err := readMockFile(mockFile); err != nil {
			log.WithError(err).Fatal("Unable to read mock file")
		}
	} else {
		synchronizeIdentities(clientset)
		synchronizeNodes(clientset)
		synchronizeCiliumEndpoints(clientset)
		operatorWatchers.StartSynchronizingServices(context.Background(), &sync.WaitGroup{}, operatorWatchers.ServiceSyncParameters{
			ServiceSyncConfiguration: cfg,

			Clientset:  clientset,
			Services:   services,
			Backend:    backend,
			SharedOnly: !cfg.enableExternalWorkloads,
		})
	}

	log.Info("Initialization complete")
}
