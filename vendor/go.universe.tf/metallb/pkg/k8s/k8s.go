package k8s // import "go.universe.tf/metallb/pkg/k8s"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.universe.tf/metallb/pkg/config"
	"go.universe.tf/metallb/pkg/k8s/types"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

// Client watches a Kubernetes cluster and translates events into
// Controller method calls.
type Client struct {
	logger log.Logger

	client *kubernetes.Clientset
	events record.EventRecorder
	queue  workqueue.RateLimitingInterface

	svcIndexer     cache.Indexer
	svcInformer    cache.Controller
	epIndexer      cache.Indexer
	epInformer     cache.Controller
	slicesIndexer  cache.Indexer
	slicesInformer cache.Controller
	cmIndexer      cache.Indexer
	cmInformer     cache.Controller
	nodeIndexer    cache.Indexer
	nodeInformer   cache.Controller

	syncFuncs []cache.InformerSynced

	serviceChanged func(log.Logger, string, *v1.Service, EpsOrSlices) types.SyncState
	configChanged  func(log.Logger, *config.Config) types.SyncState
	nodeChanged    func(log.Logger, *v1.Node) types.SyncState
	synced         func(log.Logger)
}

// Config specifies the configuration of the Kubernetes
// client/watcher.
type Config struct {
	ProcessName   string
	ConfigMapName string
	ConfigMapNS   string
	NodeName      string
	MetricsHost   string
	MetricsPort   int
	ReadEndpoints bool
	Logger        log.Logger
	Kubeconfig    string

	ServiceChanged func(log.Logger, string, *v1.Service, EpsOrSlices) types.SyncState
	ConfigChanged  func(log.Logger, *config.Config) types.SyncState
	NodeChanged    func(log.Logger, *v1.Node) types.SyncState
	Synced         func(log.Logger)
}

type svcKey string
type cmKey string
type nodeKey string
type synced string

const slicesServiceIndexName = "ServiceName"

// New connects to masterAddr, using kubeconfig to authenticate.
//
// The client uses processName to identify itself to the cluster
// (e.g. when logging events).
func New(cfg *Config) (*Client, error) {
	var (
		k8sConfig *rest.Config
		err       error
	)

	if cfg.Kubeconfig == "" {
		// if the user didn't provide a config file, assume that we're
		// running inside k8s.
		k8sConfig, err = rest.InClusterConfig()
	} else {
		// the user provided a config file, so use that.  InClusterConfig
		// would also work in this case but it emits an annoying warning.
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	}
	if err != nil {
		return nil, fmt.Errorf("building client config: %s", err)
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %s", err)
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: v1core.New(clientset.CoreV1().RESTClient()).Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: cfg.ProcessName})

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	c := &Client{
		logger: cfg.Logger,
		client: clientset,
		events: recorder,
		queue:  queue,
	}

	if cfg.ServiceChanged != nil {
		svcHandlers := cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(svcKey(key))
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					c.queue.Add(svcKey(key))
				}
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(svcKey(key))
				}
			},
		}
		svcWatcher := cache.NewListWatchFromClient(c.client.CoreV1().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
		c.svcIndexer, c.svcInformer = cache.NewIndexerInformer(svcWatcher, &v1.Service{}, 0, svcHandlers, cache.Indexers{})

		c.serviceChanged = cfg.ServiceChanged
		c.syncFuncs = append(c.syncFuncs, c.svcInformer.HasSynced)

		if cfg.ReadEndpoints {
			if !UseEndpointSlices(c.client) {
				epHandlers := cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						key, err := cache.MetaNamespaceKeyFunc(obj)
						if err == nil {
							c.queue.Add(svcKey(key))
						}
					},
					UpdateFunc: func(old interface{}, new interface{}) {
						key, err := cache.MetaNamespaceKeyFunc(new)
						if err == nil {
							c.queue.Add(svcKey(key))
						}
					},
					DeleteFunc: func(obj interface{}) {
						key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
						if err == nil {
							c.queue.Add(svcKey(key))
						}
					},
				}
				epWatcher := cache.NewListWatchFromClient(c.client.CoreV1().RESTClient(), "endpoints", v1.NamespaceAll, fields.Everything())
				c.epIndexer, c.epInformer = cache.NewIndexerInformer(epWatcher, &v1.Endpoints{}, 0, epHandlers, cache.Indexers{})

				c.syncFuncs = append(c.syncFuncs, c.epInformer.HasSynced)
			} else {
				c.logger.Log("op", "New", "msg", "using endpoint slices")
				slicesHandlers := cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						slice, ok := obj.(*discovery.EndpointSlice)
						if !ok {
							c.logger.Log("op", "SliceAdd", "error", "received a non EndpointSlice item")
							return
						}

						key, err := serviceKeyForSlice(slice)
						if err != nil {
							return
						}
						c.queue.Add(key)
					},
					UpdateFunc: func(old interface{}, new interface{}) {
						slice, ok := new.(*discovery.EndpointSlice)
						if !ok {
							c.logger.Log("op", "SliceUpdate", "error", "received a non EndpointSlice item")
							return
						}
						key, err := serviceKeyForSlice(slice)
						if err != nil {
							c.logger.Log("op", "SliceUpdate", "error", "failed to get serviceKey for slice", "slice", slice.Name)
							return
						}
						c.queue.Add(key)
					},
					DeleteFunc: func(obj interface{}) {
						slice, ok := obj.(*discovery.EndpointSlice)
						if !ok {
							c.logger.Log("op", "SliceDelete", "error", "received a non EndpointSlice item")
							return
						}
						key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(slice)
						if err != nil {
							c.logger.Log("op", "SliceDelete", "error", err)
							return
						}
						c.queue.Add(svcKey(key))
					},
				}
				slicesWatcher := cache.NewListWatchFromClient(c.client.DiscoveryV1beta1().RESTClient(), "endpointslices", v1.NamespaceAll, fields.Everything())
				c.slicesIndexer, c.slicesInformer = cache.NewIndexerInformer(slicesWatcher, &discovery.EndpointSlice{}, 5*time.Second, slicesHandlers, cache.Indexers{
					slicesServiceIndexName: slicesServiceIndex,
				})
				c.syncFuncs = append(c.syncFuncs, c.slicesInformer.HasSynced)
			}
		}
	}

	if cfg.ConfigChanged != nil {
		cmHandlers := cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(cmKey(key))
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					c.queue.Add(cmKey(key))
				}
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(cmKey(key))
				}
			},
		}
		cmWatcher := cache.NewListWatchFromClient(c.client.CoreV1().RESTClient(), "configmaps", cfg.ConfigMapNS, fields.OneTermEqualSelector("metadata.name", cfg.ConfigMapName))
		c.cmIndexer, c.cmInformer = cache.NewIndexerInformer(cmWatcher, &v1.ConfigMap{}, 0, cmHandlers, cache.Indexers{})

		c.configChanged = cfg.ConfigChanged
		c.syncFuncs = append(c.syncFuncs, c.cmInformer.HasSynced)
	}

	if cfg.NodeChanged != nil {
		nodeHandlers := cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(nodeKey(key))
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					c.queue.Add(nodeKey(key))
				}
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(nodeKey(key))
				}
			},
		}
		nodeWatcher := cache.NewListWatchFromClient(c.client.CoreV1().RESTClient(), "nodes", v1.NamespaceAll, fields.OneTermEqualSelector("metadata.name", cfg.NodeName))
		c.nodeIndexer, c.nodeInformer = cache.NewIndexerInformer(nodeWatcher, &v1.Node{}, 0, nodeHandlers, cache.Indexers{})

		c.nodeChanged = cfg.NodeChanged
		c.syncFuncs = append(c.syncFuncs, c.nodeInformer.HasSynced)
	}

	if cfg.Synced != nil {
		c.synced = cfg.Synced
	}

	http.Handle("/metrics", promhttp.Handler())
	go func(l log.Logger) {
		err := http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.MetricsHost, cfg.MetricsPort), nil)
		if err != nil {
			l.Log("op", "listenAndServe", "err", err, "msg", "cannot listen and serve", "host", cfg.MetricsHost, "port", cfg.MetricsPort)
		}
	}(c.logger)

	return c, nil
}

// CreateMlSecret create the memberlist secret.
func (c *Client) CreateMlSecret(namespace, controllerDeploymentName, secretName string) error {
	// Use List instead of Get to differentiate between API errors and non existing secret.
	// Matching error text is prone to future breakage.
	l, err := c.client.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", secretName).String(),
	})
	if err != nil {
		return err
	}
	if len(l.Items) > 0 {
		c.logger.Log("op", "CreateMlSecret", "msg", "secret already exists, nothing to do")
		return nil
	}

	// Get the controller Deployment info to set secret ownerReference.
	d, err := c.client.AppsV1().Deployments(namespace).Get(context.TODO(), controllerDeploymentName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// Create the secret key (128 bits).
	secret := make([]byte, 16)
	_, err = rand.Read(secret)
	if err != nil {
		return err
	}
	// base64 encode the secret key as it'll be passed a env variable.
	secretB64 := make([]byte, base64.RawStdEncoding.EncodedLen(len(secret)))
	base64.RawStdEncoding.Encode(secretB64, secret)

	// Create the K8S Secret object.
	_, err = c.client.CoreV1().Secrets(namespace).Create(
		context.TODO(),
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
				OwnerReferences: []metav1.OwnerReference{{
					// d.APIVersion is empty.
					APIVersion: "apps/v1",
					// d.Kind is empty.
					Kind: "Deployment",
					Name: d.Name,
					UID:  d.UID,
				}},
			},
			Data: map[string][]byte{"secretkey": secretB64},
		},
		metav1.CreateOptions{})
	if err == nil {
		c.logger.Log("op", "CreateMlSecret", "msg", "secret succesfully created")
	}
	return err
}

// PodIPs returns the IPs of all the pods matched by the labels string.
func (c *Client) PodIPs(namespace, labels string) ([]string, error) {
	pl, err := c.client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labels})
	if err != nil {
		return nil, err
	}
	iplist := []string{}
	for _, pod := range pl.Items {
		iplist = append(iplist, pod.Status.PodIP)
	}
	return iplist, nil
}

// Run watches for events on the Kubernetes cluster, and dispatches
// calls to the Controller.
func (c *Client) Run(stopCh <-chan struct{}) error {
	if c.svcInformer != nil {
		go c.svcInformer.Run(stopCh)
	}
	if c.epInformer != nil {
		go c.epInformer.Run(stopCh)
	}
	if c.slicesInformer != nil {
		go c.slicesInformer.Run(stopCh)
	}
	if c.cmInformer != nil {
		go c.cmInformer.Run(stopCh)
	}
	if c.nodeInformer != nil {
		go c.nodeInformer.Run(stopCh)
	}

	if !cache.WaitForCacheSync(stopCh, c.syncFuncs...) {
		return errors.New("timed out waiting for cache sync")
	}

	c.queue.Add(synced(""))

	if stopCh != nil {
		go func() {
			<-stopCh
			c.queue.ShutDown()
		}()
	}

	for {
		key, quit := c.queue.Get()
		if quit {
			return nil
		}
		updates.Inc()
		st := c.sync(key)
		switch st {
		case types.SyncStateSuccess:
			c.queue.Forget(key)
		case types.SyncStateError:
			updateErrors.Inc()
			c.queue.AddRateLimited(key)
		case types.SyncStateReprocessAll:
			c.queue.Forget(key)
			c.ForceSync()
		}
	}
}

// ForceSync reprocess all watched services
func (c *Client) ForceSync() {
	if c.svcIndexer != nil {
		for _, k := range c.svcIndexer.ListKeys() {
			c.queue.AddRateLimited(svcKey(k))
		}
	}
}

// UpdateStatus writes the protected "status" field of svc back into
// the Kubernetes cluster.
func (c *Client) UpdateStatus(svc *v1.Service) error {
	_, err := c.client.CoreV1().Services(svc.Namespace).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
	return err
}

// Infof logs an informational event about svc to the Kubernetes cluster.
func (c *Client) Infof(svc *v1.Service, kind, msg string, args ...interface{}) {
	c.events.Eventf(svc, v1.EventTypeNormal, kind, msg, args...)
}

// Errorf logs an error event about svc to the Kubernetes cluster.
func (c *Client) Errorf(svc *v1.Service, kind, msg string, args ...interface{}) {
	c.events.Eventf(svc, v1.EventTypeWarning, kind, msg, args...)
}

func (c *Client) sync(key interface{}) types.SyncState {
	defer c.queue.Done(key)

	switch k := key.(type) {
	case svcKey:
		l := log.With(c.logger, "service", string(k))
		svc, exists, err := c.svcIndexer.GetByKey(string(k))
		if err != nil {
			l.Log("op", "getService", "error", err, "msg", "failed to get service")
			return types.SyncStateError
		}
		if !exists {
			return c.serviceChanged(l, string(k), nil, EpsOrSlices{})
		}

		epsOrSlices := EpsOrSlices{}
		if c.epIndexer != nil {
			epsIntf, exists, err := c.epIndexer.GetByKey(string(k))
			if err != nil {
				l.Log("op", "getEndpoints", "error", err, "msg", "failed to get endpoints")
				return types.SyncStateError
			}
			if !exists {
				return c.serviceChanged(l, string(k), nil, EpsOrSlices{})
			}

			eps := epsIntf.(*v1.Endpoints)
			epsOrSlices.EpVal = eps.DeepCopy()
			epsOrSlices.Type = Eps
		}
		if c.slicesIndexer != nil {
			slicesIntf, err := c.slicesIndexer.ByIndex(slicesServiceIndexName, string(k))
			if err != nil {
				l.Log("op", "getEndpointSlices", "error", err, "msg", "failed to get endpoints slices")
				return types.SyncStateError
			}
			if len(slicesIntf) == 0 {
				return c.serviceChanged(l, string(k), nil, EpsOrSlices{})
			}
			epsOrSlices.SlicesVal = make([]*discovery.EndpointSlice, 0)
			for _, s := range slicesIntf {
				slice, ok := s.(*discovery.EndpointSlice)
				if !ok {
					continue
				}
				epsOrSlices.SlicesVal = append(epsOrSlices.SlicesVal, slice.DeepCopy())
			}
			epsOrSlices.Type = Slices
		}
		return c.serviceChanged(l, string(k), svc.(*v1.Service), epsOrSlices)

	case cmKey:
		l := log.With(c.logger, "configmap", string(k))
		cmi, exists, err := c.cmIndexer.GetByKey(string(k))
		if err != nil {
			l.Log("op", "getConfigMap", "error", err, "msg", "failed to get configmap")
			return types.SyncStateError
		}
		if !exists {
			configStale.Set(1)
			return c.configChanged(l, nil)
		}

		// Note that configs that we can read, but that fail parsing
		// or validation, result in a "synced" state, because the
		// config is not going to parse any better until the k8s
		// object changes to fix the issue.
		cm := cmi.(*v1.ConfigMap)
		cfg, err := config.Parse([]byte(cm.Data["config"]))
		if err != nil {
			l.Log("event", "configStale", "error", err, "msg", "config (re)load failed, config marked stale")
			configStale.Set(1)
			return types.SyncStateSuccess
		}

		st := c.configChanged(l, cfg)
		if st == types.SyncStateError {
			l.Log("event", "configStale", "error", err, "msg", "config (re)load failed, config marked stale")
			configStale.Set(1)
			return types.SyncStateSuccess
		}

		configLoaded.Set(1)
		configStale.Set(0)

		l.Log("event", "configLoaded", "msg", "config (re)loaded")
		return st

	case nodeKey:
		l := log.With(c.logger, "node", string(k))
		n, exists, err := c.nodeIndexer.GetByKey(string(k))
		if err != nil {
			l.Log("op", "getNode", "error", err, "msg", "failed to get node")
			return types.SyncStateError
		}
		if !exists {
			l.Log("op", "getNode", "error", "node doesn't exist in k8s, but I'm running on it!")
			return types.SyncStateError
		}
		node := n.(*v1.Node)
		return c.nodeChanged(c.logger, node)

	case synced:
		if c.synced != nil {
			c.synced(c.logger)
		}
		return types.SyncStateSuccess

	default:
		panic(fmt.Errorf("unknown key type for %#v (%T)", key, key))
	}
}

func serviceKeyForSlice(endpointSlice *discovery.EndpointSlice) (svcKey, error) {
	if endpointSlice == nil {
		return "", fmt.Errorf("nil EndpointSlice")
	}
	serviceName, err := serviceNameForSlice(endpointSlice)
	if err != nil {
		return "", err
	}
	return svcKey(fmt.Sprintf("%s/%s", endpointSlice.Namespace, serviceName)), nil
}

func slicesServiceIndex(obj interface{}) ([]string, error) {
	endpointSlice, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		return nil, fmt.Errorf("Passed object is not a slice")
	}
	serviceKey, err := serviceKeyForSlice(endpointSlice)
	if err != nil {
		return nil, err
	}
	return []string{string(serviceKey)}, nil
}

func serviceNameForSlice(endpointSlice *discovery.EndpointSlice) (string, error) {
	serviceName, ok := endpointSlice.Labels["kubernetes.io/service-name"]
	if !ok || serviceName == "" {
		return "", fmt.Errorf("endpointSlice missing %s label", "kubernetes.io/service-name")
	}
	return serviceName, nil
}

// UseEndpointSlices detect if Endpoints Slices are enabled in the cluster
func UseEndpointSlices(kubeClient kubernetes.Interface) bool {
	if _, err := kubeClient.Discovery().ServerResourcesForGroupVersion(discovery.SchemeGroupVersion.String()); err != nil {
		return false
	}
	// this is needed to check if ep slices are enabled on the cluster. In 1.17 the resources are there but disabled by default
	if _, err := kubeClient.DiscoveryV1beta1().EndpointSlices("default").Get(context.Background(), "kubernetes", metav1.GetOptions{}); err != nil {
		return false
	}
	return true
}
