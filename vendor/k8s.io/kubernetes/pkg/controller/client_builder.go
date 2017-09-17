/*
Copyright 2016 The Kubernetes Authors.

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

package controller

import (
	"fmt"
	"time"

	v1authenticationapi "k8s.io/api/authentication/v1"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
	clientgoclientset "k8s.io/client-go/kubernetes"
	clientset "k8s.io/client-go/kubernetes"
	v1authentication "k8s.io/client-go/kubernetes/typed/authentication/v1"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/serviceaccount"

	"github.com/golang/glog"
)

// ControllerClientBuilder allows you to get clients and configs for controllers
type ControllerClientBuilder interface {
	Config(name string) (*restclient.Config, error)
	ConfigOrDie(name string) *restclient.Config
	Client(name string) (clientset.Interface, error)
	ClientOrDie(name string) clientset.Interface
	ClientGoClient(name string) (clientgoclientset.Interface, error)
	ClientGoClientOrDie(name string) clientgoclientset.Interface
}

// SimpleControllerClientBuilder returns a fixed client with different user agents
type SimpleControllerClientBuilder struct {
	// ClientConfig is a skeleton config to clone and use as the basis for each controller client
	ClientConfig *restclient.Config
}

func (b SimpleControllerClientBuilder) Config(name string) (*restclient.Config, error) {
	clientConfig := *b.ClientConfig
	return restclient.AddUserAgent(&clientConfig, name), nil
}

func (b SimpleControllerClientBuilder) ConfigOrDie(name string) *restclient.Config {
	clientConfig, err := b.Config(name)
	if err != nil {
		glog.Fatal(err)
	}
	return clientConfig
}

func (b SimpleControllerClientBuilder) Client(name string) (clientset.Interface, error) {
	clientConfig, err := b.Config(name)
	if err != nil {
		return nil, err
	}
	return clientset.NewForConfig(clientConfig)
}

func (b SimpleControllerClientBuilder) ClientOrDie(name string) clientset.Interface {
	client, err := b.Client(name)
	if err != nil {
		glog.Fatal(err)
	}
	return client
}

func (b SimpleControllerClientBuilder) ClientGoClient(name string) (clientgoclientset.Interface, error) {
	clientConfig, err := b.Config(name)
	if err != nil {
		return nil, err
	}
	return clientgoclientset.NewForConfig(clientConfig)
}

func (b SimpleControllerClientBuilder) ClientGoClientOrDie(name string) clientgoclientset.Interface {
	client, err := b.ClientGoClient(name)
	if err != nil {
		glog.Fatal(err)
	}
	return client
}

// SAControllerClientBuilder is a ControllerClientBuilder that returns clients identifying as
// service accounts
type SAControllerClientBuilder struct {
	// ClientConfig is a skeleton config to clone and use as the basis for each controller client
	ClientConfig *restclient.Config

	// CoreClient is used to provision service accounts if needed and watch for their associated tokens
	// to construct a controller client
	CoreClient v1core.CoreV1Interface

	// AuthenticationClient is used to check API tokens to make sure they are valid before
	// building a controller client from them
	AuthenticationClient v1authentication.AuthenticationV1Interface

	// Namespace is the namespace used to host the service accounts that will back the
	// controllers.  It must be highly privileged namespace which normal users cannot inspect.
	Namespace string
}

// config returns a complete clientConfig for constructing clients.  This is separate in anticipation of composition
// which means that not all clientsets are known here
func (b SAControllerClientBuilder) Config(name string) (*restclient.Config, error) {
	sa, err := b.getOrCreateServiceAccount(name)
	if err != nil {
		return nil, err
	}

	var clientConfig *restclient.Config

	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fields.SelectorFromSet(map[string]string{api.SecretTypeField: string(v1.SecretTypeServiceAccountToken)}).String()
			return b.CoreClient.Secrets(b.Namespace).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fields.SelectorFromSet(map[string]string{api.SecretTypeField: string(v1.SecretTypeServiceAccountToken)}).String()
			return b.CoreClient.Secrets(b.Namespace).Watch(options)
		},
	}
	_, err = cache.ListWatchUntil(30*time.Second, lw,
		func(event watch.Event) (bool, error) {
			switch event.Type {
			case watch.Deleted:
				return false, nil
			case watch.Error:
				return false, fmt.Errorf("error watching")

			case watch.Added, watch.Modified:
				secret, ok := event.Object.(*v1.Secret)
				if !ok {
					return false, fmt.Errorf("unexpected object type: %T", event.Object)
				}
				if !serviceaccount.IsServiceAccountToken(secret, sa) {
					return false, nil
				}
				if len(secret.Data[v1.ServiceAccountTokenKey]) == 0 {
					return false, nil
				}
				validConfig, valid, err := b.getAuthenticatedConfig(sa, string(secret.Data[v1.ServiceAccountTokenKey]))
				if err != nil {
					glog.Warningf("error validating API token for %s/%s in secret %s: %v", sa.Name, sa.Namespace, secret.Name, err)
					// continue watching for good tokens
					return false, nil
				}
				if !valid {
					glog.Warningf("secret %s contained an invalid API token for %s/%s", secret.Name, sa.Name, sa.Namespace)
					// try to delete the secret containing the invalid token
					if err := b.CoreClient.Secrets(secret.Namespace).Delete(secret.Name, &metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
						glog.Warningf("error deleting secret %s containing invalid API token for %s/%s: %v", secret.Name, sa.Name, sa.Namespace, err)
					}
					// continue watching for good tokens
					return false, nil
				}
				clientConfig = validConfig
				return true, nil

			default:
				return false, fmt.Errorf("unexpected event type: %v", event.Type)
			}
		})
	if err != nil {
		return nil, fmt.Errorf("unable to get token for service account: %v", err)
	}

	return clientConfig, nil
}

func (b SAControllerClientBuilder) getOrCreateServiceAccount(name string) (*v1.ServiceAccount, error) {
	sa, err := b.CoreClient.ServiceAccounts(b.Namespace).Get(name, metav1.GetOptions{})
	if err == nil {
		return sa, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	// Create the namespace if we can't verify it exists.
	// Tolerate errors, since we don't know whether this component has namespace creation permissions.
	if _, err := b.CoreClient.Namespaces().Get(b.Namespace, metav1.GetOptions{}); err != nil {
		b.CoreClient.Namespaces().Create(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: b.Namespace}})
	}

	// Create the service account
	sa, err = b.CoreClient.ServiceAccounts(b.Namespace).Create(&v1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: b.Namespace, Name: name}})
	if apierrors.IsAlreadyExists(err) {
		// If we're racing to init and someone else already created it, re-fetch
		return b.CoreClient.ServiceAccounts(b.Namespace).Get(name, metav1.GetOptions{})
	}
	return sa, err
}

func (b SAControllerClientBuilder) getAuthenticatedConfig(sa *v1.ServiceAccount, token string) (*restclient.Config, bool, error) {
	username := apiserverserviceaccount.MakeUsername(sa.Namespace, sa.Name)

	clientConfig := restclient.AnonymousClientConfig(b.ClientConfig)
	clientConfig.BearerToken = token
	restclient.AddUserAgent(clientConfig, username)

	// Try token review first
	tokenReview := &v1authenticationapi.TokenReview{Spec: v1authenticationapi.TokenReviewSpec{Token: token}}
	if tokenResult, err := b.AuthenticationClient.TokenReviews().Create(tokenReview); err == nil {
		if !tokenResult.Status.Authenticated {
			glog.Warningf("Token for %s/%s did not authenticate correctly", sa.Name, sa.Namespace)
			return nil, false, nil
		}
		if tokenResult.Status.User.Username != username {
			glog.Warningf("Token for %s/%s authenticated as unexpected username: %s", sa.Name, sa.Namespace, tokenResult.Status.User.Username)
			return nil, false, nil
		}
		glog.V(4).Infof("Verified credential for %s/%s", sa.Name, sa.Namespace)
		return clientConfig, true, nil
	}

	// If we couldn't run the token review, the API might be disabled or we might not have permission.
	// Try to make a request to /apis with the token. If we get a 401 we should consider the token invalid.
	clientConfigCopy := *clientConfig
	clientConfigCopy.NegotiatedSerializer = api.Codecs
	client, err := restclient.UnversionedRESTClientFor(&clientConfigCopy)
	if err != nil {
		return nil, false, err
	}
	err = client.Get().AbsPath("/apis").Do().Error()
	if apierrors.IsUnauthorized(err) {
		glog.Warningf("Token for %s/%s did not authenticate correctly: %v", sa.Name, sa.Namespace, err)
		return nil, false, nil
	}

	return clientConfig, true, nil
}

func (b SAControllerClientBuilder) ConfigOrDie(name string) *restclient.Config {
	clientConfig, err := b.Config(name)
	if err != nil {
		glog.Fatal(err)
	}
	return clientConfig
}

func (b SAControllerClientBuilder) Client(name string) (clientset.Interface, error) {
	clientConfig, err := b.Config(name)
	if err != nil {
		return nil, err
	}
	return clientset.NewForConfig(clientConfig)
}

func (b SAControllerClientBuilder) ClientOrDie(name string) clientset.Interface {
	client, err := b.Client(name)
	if err != nil {
		glog.Fatal(err)
	}
	return client
}

func (b SAControllerClientBuilder) ClientGoClient(name string) (clientgoclientset.Interface, error) {
	clientConfig, err := b.Config(name)
	if err != nil {
		return nil, err
	}
	return clientgoclientset.NewForConfig(clientConfig)
}

func (b SAControllerClientBuilder) ClientGoClientOrDie(name string) clientgoclientset.Interface {
	client, err := b.ClientGoClient(name)
	if err != nil {
		glog.Fatal(err)
	}
	return client
}
