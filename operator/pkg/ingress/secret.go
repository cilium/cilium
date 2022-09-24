// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	type_corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	tlsFieldSelector = "type=kubernetes.io/tls"
)

type secretManager interface {
	// Run kicks off the control loop for queue processing
	Run()

	// Add publishes event to queue
	Add(event interface{})
}

type secretAddedEvent struct {
	secret *slim_corev1.Secret
}

type secretUpdatedEvent struct {
	oldSecret *slim_corev1.Secret
	newSecret *slim_corev1.Secret
}

type secretDeletedEvent struct {
	secret *slim_corev1.Secret
}

type syncSecretManager struct {
	informer cache.Controller
	store    cache.Store
	queue    workqueue.RateLimitingInterface

	maxRetries int
	namespace  string

	client type_corev1.SecretInterface

	lock lock.RWMutex

	// watchedSecretMap contains mappings for original and synced TLS secrets.
	watchedSecretMap map[string]string
}

type noOpsSecretManager struct{}

// newNoOpsSecretManager returns new no-ops instance of secret manager
func newNoOpsSecretManager() secretManager {
	return noOpsSecretManager{}
}

func (n noOpsSecretManager) Run() {}

func (n noOpsSecretManager) Add(event interface{}) {}

// newSyncSecretsManager constructs a new secret manager instance
func newSyncSecretsManager(clientset k8sClient.Clientset, namespace string, maxRetries int) (secretManager, error) {
	manager := &syncSecretManager{
		queue:            workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		namespace:        namespace,
		maxRetries:       maxRetries,
		client:           clientset.CoreV1().Secrets(namespace),
		watchedSecretMap: map[string]string{},
	}

	manager.store, manager.informer = informer.NewInformer(
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*slim_corev1.SecretList](clientset.Slim().CoreV1().Secrets(corev1.NamespaceAll)),
			// only watch TLS secret
			func(options *metav1.ListOptions) {
				options.FieldSelector = tlsFieldSelector
			}),
		&slim_corev1.Secret{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if secret := k8s.ObjToV1Secret(obj); secret != nil {
					manager.queue.Add(secretAddedEvent{secret: secret})
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldSecret := k8s.ObjToV1Secret(oldObj)
				if oldSecret == nil {
					return
				}
				newSecret := k8s.ObjToV1Secret(newObj)
				if newSecret == nil {
					return
				}
				if oldSecret.DeepEqual(newSecret) {
					return
				}
				manager.queue.Add(secretUpdatedEvent{oldSecret: oldSecret, newSecret: newSecret})
			},
			DeleteFunc: func(obj interface{}) {
				if secret := k8s.ObjToV1Secret(obj); secret != nil {
					manager.queue.Add(secretDeletedEvent{secret: secret})
				}
			},
		},
		nil,
	)

	go manager.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync secrets")
	}
	return manager, nil
}

func (sm *syncSecretManager) Run() {
	defer sm.queue.ShutDown()
	go sm.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, sm.informer.HasSynced) {
		return
	}
	for sm.processEvent() {
	}
}

func (sm *syncSecretManager) Add(event interface{}) {
	sm.queue.Add(event)
}

// getByKey is a wrapper of Store.GetByKey but with concrete Secret object
func (sm *syncSecretManager) getByKey(key string) (*slim_corev1.Secret, bool, error) {
	objFromCache, exists, err := sm.store.GetByKey(key)
	if objFromCache == nil || !exists || err != nil {
		return nil, exists, err
	}

	s, ok := objFromCache.(*slim_corev1.Secret)
	if !ok {
		return nil, exists, fmt.Errorf("unexpected type found in service cache: %T", objFromCache)
	}
	return s, exists, err
}

func (sm *syncSecretManager) processEvent() bool {
	event, shutdown := sm.queue.Get()
	if shutdown {
		return false
	}
	defer sm.queue.Done(event)
	err := sm.handleEvent(event)
	if err == nil {
		sm.queue.Forget(event)
	} else if sm.queue.NumRequeues(event) < sm.maxRetries {
		sm.queue.AddRateLimited(event)
	} else {
		log.Errorf("Failed to process Ingress event, skipping: %+v", event)
		sm.queue.Forget(event)
	}
	return true
}

func (sm *syncSecretManager) handleEvent(event interface{}) interface{} {
	var err error
	switch ev := event.(type) {
	case secretAddedEvent:
		err = sm.handleSecretAddedEvent(ev)
	case secretUpdatedEvent:
		err = sm.handleSecretUpdatedEvent(ev)
	case secretDeletedEvent:
		err = sm.handleSecretDeletedEvent(ev)
	case ingressAddedEvent:
		err = sm.handleIngressAddedEvent(ev)
	case ingressUpdatedEvent:
		err = sm.handleIngressUpdatedEvent(ev)
	case ingressDeletedEvent:
		err = sm.handleIngressDeletedEvent(ev)
	default:
		err = fmt.Errorf("received an unknown event: %t", ev)
	}
	return err
}

func (sm *syncSecretManager) handleSecretAddedEvent(ev secretAddedEvent) error {
	if ev.secret.GetNamespace() == sm.namespace {
		return nil
	}
	return sm.syncSecret(ev.secret)
}

func (sm *syncSecretManager) handleSecretUpdatedEvent(ev secretUpdatedEvent) error {
	if ev.oldSecret.GetNamespace() == sm.namespace || ev.newSecret.GetNamespace() == sm.namespace {
		return nil
	}
	return sm.syncSecret(ev.newSecret)
}

func (sm *syncSecretManager) handleSecretDeletedEvent(ev secretDeletedEvent) error {
	if ev.secret.GetNamespace() == sm.namespace {
		return nil
	}
	return sm.deleteSecret(ev.secret)
}

func (sm *syncSecretManager) handleIngressAddedEvent(ev ingressAddedEvent) error {
	return sm.handleIngressUpsertedEvent(ev.ingress)
}

func (sm *syncSecretManager) handleIngressUpdatedEvent(ev ingressUpdatedEvent) error {
	return sm.handleIngressUpsertedEvent(ev.newIngress)
}

// handleIngressDeletedEvent is doing nothing right now as the underlying secrets could be
// referenced in other Ingress resources, which is common use case for wildcard secrets (e.g
// *.foo.com)
func (sm *syncSecretManager) handleIngressDeletedEvent(ev ingressDeletedEvent) error {
	return nil
}

func (sm *syncSecretManager) handleIngressUpsertedEvent(ingress *slim_networkingv1.Ingress) error {
	for _, tls := range ingress.Spec.TLS {
		// check if the secret is available
		key := getSecretKey(ingress.GetNamespace(), tls.SecretName)
		secret, exists, err := sm.getByKey(key)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("secret does not exist: %s", key)
		}

		sm.lock.Lock()
		sm.watchedSecretMap[key] = getSyncedSecretKey(sm.namespace, secret.GetNamespace(), secret.GetName())
		sm.lock.Unlock()

		// proceed to sync secret
		err = sm.syncSecret(secret)
		if err != nil {
			return err
		}
	}
	return nil
}

// syncSecret performs an upsert to make sure that secret in secret namespace is in synced with original secret
func (sm *syncSecretManager) syncSecret(original *slim_corev1.Secret) error {
	key := getSecretKey(original.GetNamespace(), original.GetName())
	sm.lock.RLock()
	_, exists := sm.watchedSecretMap[key]
	sm.lock.RUnlock()
	if !exists {
		// the secret is not used in TLS, ignoring.
		return nil
	}

	syncKey := getSyncedSecretKey(sm.namespace, original.GetNamespace(), original.GetName())

	scopedLog := log.WithField("secret", key).WithField("synced-secret", syncKey)
	syncedSecret, exists, err := sm.getByKey(syncKey)
	if err != nil {
		scopedLog.WithError(err).Errorf("Unable to lookup secret")
		return err
	}

	// create a new secret if not exits
	if !exists {
		newSecret := original.DeepCopy()
		newSecret.Name = getSyncedSecretName(original.GetNamespace(), original.GetName())
		newSecret.Namespace = sm.namespace

		// create a new secret
		_, err = sm.client.Create(context.TODO(), toV1Secret(newSecret), metav1.CreateOptions{})
		if err != nil {
			scopedLog.WithError(err).Errorf("Unable to create secret")
			return err
		}
		return nil
	}

	// check if the values are in synced
	// DeepEqual can't be used here due to namespace changes
	if reflect.DeepEqual(original.StringData, syncedSecret.StringData) &&
		reflect.DeepEqual(original.Data, syncedSecret.Data) {
		return nil
	}

	// update existing secret
	newSecret := syncedSecret.DeepCopy()
	newSecret.Data = original.Data
	newSecret.StringData = original.StringData

	_, err = sm.client.Update(context.TODO(), toV1Secret(newSecret), metav1.UpdateOptions{})
	if err != nil {
		scopedLog.WithError(err).Errorf("Unable to update secret")
		return err
	}
	return nil
}

// deleteSecret removes synced secret in secret namespace
func (sm *syncSecretManager) deleteSecret(original *slim_corev1.Secret) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	key := getSecretKey(original.GetNamespace(), original.GetName())
	scopedLog := log.WithField("secret", key)

	if _, exists := sm.watchedSecretMap[key]; exists {
		err := sm.client.Delete(context.TODO(), getSyncedSecretName(original.GetNamespace(), original.GetName()),
			metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			scopedLog.WithError(err).Errorf("Unable to delete secret")
			return err
		}
		delete(sm.watchedSecretMap, key)
	}
	return nil
}

func getSecretKey(namespace string, secretName string) string {
	return fmt.Sprintf("%s/%s", namespace, secretName)
}

func getSyncedSecretKey(syncedNamespace string, originalNamespace string, secretName string) string {
	return fmt.Sprintf("%s/%s-%s", syncedNamespace, originalNamespace, secretName)
}

func getSyncedSecretName(originalNamespace string, secretName string) string {
	return fmt.Sprintf("%s-%s", originalNamespace, secretName)
}

func toV1Secret(in *slim_corev1.Secret) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       in.Kind,
			APIVersion: in.APIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        in.Name,
			Namespace:   in.Namespace,
			Labels:      in.Labels,
			Annotations: in.Annotations,
		},
		StringData: in.StringData,
		Data:       convertMap(in.Data),
		Type:       corev1.SecretType(in.Type),
	}
}

func convertMap(in map[string]slim_corev1.Bytes) map[string][]byte {
	out := make(map[string][]byte)
	for k, v := range in {
		out[k] = v
	}
	return out
}
