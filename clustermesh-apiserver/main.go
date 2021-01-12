// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"reflect"
	"strings"
	"time"

	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

type configuration struct {
	clusterName      string
	serviceProxyName string
}

func (c configuration) LocalClusterName() string {
	return c.clusterName
}

func (c configuration) K8sServiceProxyName() string {
	return c.serviceProxyName
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "clustermesh-apiserver")

	rootCmd = &cobra.Command{
		Use:   "clustermesh-apiserver",
		Short: "Run the ClusterMesh apiserver",
		Run: func(cmd *cobra.Command, args []string) {
			// Open socket for using gops to get stacktraces of the agent.
			addr := fmt.Sprintf("127.0.0.1:%d", viper.GetInt(option.GopsPort))
			addrField := logrus.Fields{"address": addr}
			if err := gops.Listen(gops.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			}); err != nil {
				log.WithError(err).WithFields(addrField).Fatal("Cannot start gops server")
			}
			log.WithFields(addrField).Info("Started gops server")

			runServer(cmd)
		},
	}

	mockFile        string
	clusterID       int
	ciliumK8sClient clientset.Interface
	cfg             configuration

	shutdownSignal = make(chan struct{})

	ciliumNodeRegisterStore *store.SharedStore
	ciliumNodeStore         *store.SharedStore

	identityStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
)

func installSigHandler() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM)

	go func() {
		<-signals
		close(shutdownSignal)
	}()
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
				updateEndpoint(&endpoint)
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
	option.BindEnv(option.DebugArg)

	flags.Int(option.GopsPort, defaults.GopsPortApiserver, "Port for gops server to listen on")
	option.BindEnv(option.GopsPort)

	flags.Duration(option.CRDWaitTimeout, 5*time.Minute, "Cilium will exit if CRDs are not available within this duration upon startup")
	option.BindEnv(option.CRDWaitTimeout)

	flags.String(option.IdentityAllocationMode, option.IdentityAllocationModeCRD, "Method to use for identity allocation")
	option.BindEnv(option.IdentityAllocationMode)

	flags.IntVar(&clusterID, option.ClusterIDName, 0, "Cluster ID")
	option.BindEnv(option.ClusterIDName)

	flags.StringVar(&cfg.clusterName, option.ClusterName, "default", "Cluster name")
	option.BindEnv(option.ClusterName)

	flags.StringVar(&mockFile, "mock-file", "", "Read from mock file")

	flags.Duration(option.KVstoreConnectivityTimeout, defaults.KVstoreConnectivityTimeout, "Time after which an incomplete kvstore operation  is considered failed")
	option.BindEnv(option.KVstoreConnectivityTimeout)

	flags.Duration(option.KVstoreLeaseTTL, defaults.KVstoreLeaseTTL, "Time-to-live for the KVstore lease.")
	flags.MarkHidden(option.KVstoreLeaseTTL)
	option.BindEnv(option.KVstoreLeaseTTL)

	flags.Duration(option.KVstorePeriodicSync, defaults.KVstorePeriodicSync, "Periodic KVstore synchronization interval")
	option.BindEnv(option.KVstorePeriodicSync)

	flags.Var(option.NewNamedMapOptions(option.KVStoreOpt, &option.Config.KVStoreOpt, nil),
		option.KVStoreOpt, "Key-value store options")
	option.BindEnv(option.KVStoreOpt)

	flags.StringVar(&cfg.serviceProxyName, option.K8sServiceProxyName, "", "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
	option.BindEnv(option.K8sServiceProxyName)

	viper.BindPFlags(flags)
	option.Config.Populate()

	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}

func main() {
	installSigHandler()

	if err := runApiserver(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startApi() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		statusCode := http.StatusOK
		reply := "ok"

		if _, err := k8s.Client().Discovery().ServerVersion(); err != nil {
			statusCode = http.StatusInternalServerError
			reply = err.Error()
		}
		w.WriteHeader(statusCode)
		if _, err := w.Write([]byte(reply)); err != nil {
			log.WithError(err).Error("Failed to respond to /healthz request")
		}
	})

	srv := &http.Server{}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.WithError(err).Fatalf("Unable to start health API")
		}

		<-shutdownSignal
		if err := srv.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("Unable to shutdown health API")
		}
	}()
	log.Info("Started health API")
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
		key = append(key, []byte(l.FormatForKVStore())...)
	}

	if len(key) == 0 {
		return
	}

	keyEncoded := []byte(kvstore.Client().Encode(key))
	log.WithFields(logrus.Fields{"key": keyPath, "value": string(keyEncoded)}).Info("Updating identity in etcd")

	_, err := kvstore.Client().UpdateIfDifferent(context.Background(), keyPath, keyEncoded, true)
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
	err := kvstore.Client().Delete(context.Background(), keyPath)
	if err != nil {
		log.WithError(err).Warningf("Unable to delete identity %s in etcd", keyPath)
	}
}

func synchronizeIdentities() {
	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
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

type nodeStub string

func (n nodeStub) GetKeyName() string { return string(n) }

func updateNode(obj interface{}) {
	if ciliumNode, ok := obj.(*ciliumv2.CiliumNode); ok {
		n := nodeTypes.ParseCiliumNode(ciliumNode)
		n.Cluster = cfg.clusterName
		n.ClusterID = clusterID
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
		ciliumNodeStore.DeleteLocalKey(context.Background(), nodeStub(n.Name))
	} else {
		log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
	}
}

func synchronizeNodes() {
	_, ciliumNodeInformer := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
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

func updateEndpoint(obj interface{}) {
	e, ok := obj.(*types.CiliumEndpoint)
	if !ok {
		log.Warningf("Unknown CiliumEndpoint object type %s received: %+v", reflect.TypeOf(obj), obj)
		return
	}

	if n := e.Networking; n != nil {
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
					K8sNamespace: e.Namespace,
					K8sPodName:   e.Name,
				}

				if e.Identity != nil {
					entry.ID = identity.NumericIdentity(e.Identity.ID)
				}

				if e.Encryption != nil {
					entry.Key = uint8(e.Encryption.Key)
				}

				marshaledEntry, err := json.Marshal(entry)
				if err != nil {
					log.WithError(err).Warningf("Unable to JSON marshal entry %#v", entry)
					continue
				}

				_, err = kvstore.Client().UpdateIfDifferent(context.Background(), keyPath, marshaledEntry, true)
				if err != nil {
					log.WithError(err).Warningf("Unable to update endpoint %s in etcd", keyPath)
				} else {
					log.Infof("Inserted endpoint into etcd: %v", entry)
				}
			}
		}
	}
}

func deleteEndpoint(obj interface{}) {
	e, ok := obj.(*types.CiliumEndpoint)
	if !ok {
		log.Warningf("Unknown CiliumEndpoint object type %s received: %+v", reflect.TypeOf(obj), obj)
		return
	}

	if n := e.Networking; n != nil {
		for _, address := range n.Addressing {
			for _, ip := range []string{address.IPV4, address.IPV6} {
				if ip == "" {
					continue
				}

				keyPath := path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace, ip)
				if err := kvstore.Client().Delete(context.Background(), keyPath); err != nil {
					log.WithError(err).Warningf("Unable to delete endpoint %s in etcd", keyPath)
				}
			}
		}
	}
}

func synchronizeCiliumEndpoints() {
	_, ciliumNodeInformer := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			"ciliumendpoints", k8sv1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumEndpoint{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: updateEndpoint,
			UpdateFunc: func(_, newObj interface{}) {
				updateEndpoint(newObj)
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

	go ciliumNodeInformer.Run(wait.NeverStop)
}

func runServer(cmd *cobra.Command) {
	log.WithFields(logrus.Fields{
		"cluster-name": cfg.clusterName,
		"cluster-id":   clusterID,
	}).Info("Starting clustermesh-apiserver...")

	if mockFile == "" {
		k8s.Configure("", "", 0.0, 0)
		if err := k8s.Init(k8sconfig.NewDefaultConfiguration()); err != nil {
			log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
		}
		synced.SyncCRDs(context.TODO(), synced.AllCRDResourceNames, &synced.Resources{}, &synced.APIGroups{})
		ciliumK8sClient = k8s.CiliumClient()
	}

	mgr := NewVMManager(ciliumK8sClient)

	go startApi()

	var err error
	if err = kvstore.Setup(context.Background(), "etcd", option.Config.KVStoreOpt, nil); err != nil {
		log.WithError(err).Fatal("Unable to connect to etcd")
	}

	ciliumNodeRegisterStore, err = store.JoinSharedStore(store.Configuration{
		Prefix:     nodeStore.NodeRegisterStorePrefix,
		KeyCreator: nodeStore.RegisterKeyCreator,
		Observer:   mgr,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to set up node store in etcd")
	}

	ciliumNodeStore, err = store.JoinSharedStore(store.Configuration{
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
		synchronizeIdentities()
		synchronizeNodes()
		synchronizeCiliumEndpoints()
		operatorWatchers.StartSynchronizingServices(false, cfg)
	}

	go func() {
		timer, timerDone := inctimer.New()
		defer timerDone()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), defaults.LockLeaseTTL)
			err := kvstore.Client().Update(ctx, kvstore.HeartbeatPath, []byte(time.Now().Format(time.RFC3339)), true)
			if err != nil {
				log.WithError(err).Warning("Unable to update heartbeat key")
			}
			cancel()
			<-timer.After(kvstore.HeartbeatWriteInterval)
		}
	}()

	log.Info("Initialization complete")

	<-shutdownSignal
	log.Info("Received termination signal. Shutting down")
	return
}
