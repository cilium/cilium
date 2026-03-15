/*
Copyright 2019 The Kubernetes Authors.

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

package builder

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"
)

// WebhookBuilder builds a Webhook.
type WebhookBuilder[T runtime.Object] struct {
	apiType                   runtime.Object
	customDefaulter           admission.CustomDefaulter //nolint:staticcheck
	defaulter                 admission.Defaulter[T]
	customDefaulterOpts       []admission.DefaulterOption
	customValidator           admission.CustomValidator //nolint:staticcheck
	validator                 admission.Validator[T]
	customPath                string
	customValidatorCustomPath string
	customDefaulterCustomPath string
	converterConstructor      func(*runtime.Scheme) (conversion.Converter, error)
	gvk                       schema.GroupVersionKind
	mgr                       manager.Manager
	config                    *rest.Config
	recoverPanic              *bool
	logConstructor            func(base logr.Logger, req *admission.Request) logr.Logger
	contextFunc               func(context.Context, *http.Request) context.Context
	err                       error
}

// WebhookManagedBy returns a new webhook builder.
func WebhookManagedBy[T runtime.Object](m manager.Manager, object T) *WebhookBuilder[T] {
	return &WebhookBuilder[T]{mgr: m, apiType: object}
}

// WithCustomDefaulter takes an admission.CustomDefaulter interface, a MutatingWebhook with the provided opts (admission.DefaulterOption)
// will be wired for this type.
//
// Deprecated: Use WithDefaulter instead.
func (blder *WebhookBuilder[T]) WithCustomDefaulter(defaulter admission.CustomDefaulter, opts ...admission.DefaulterOption) *WebhookBuilder[T] {
	blder.customDefaulter = defaulter
	blder.customDefaulterOpts = opts
	return blder
}

// WithDefaulter sets up the provided admission.Defaulter in a defaulting webhook.
func (blder *WebhookBuilder[T]) WithDefaulter(defaulter admission.Defaulter[T], opts ...admission.DefaulterOption) *WebhookBuilder[T] {
	blder.defaulter = defaulter
	blder.customDefaulterOpts = opts
	return blder
}

// WithCustomValidator takes a admission.CustomValidator interface, a ValidatingWebhook will be wired for this type.
//
// Deprecated: Use WithValidator instead.
func (blder *WebhookBuilder[T]) WithCustomValidator(validator admission.CustomValidator) *WebhookBuilder[T] {
	blder.customValidator = validator
	return blder
}

// WithValidator sets up the provided admission.Validator in a validating webhook.
func (blder *WebhookBuilder[T]) WithValidator(validator admission.Validator[T]) *WebhookBuilder[T] {
	blder.validator = validator
	return blder
}

// WithConverter takes a func that constructs a converter.Converter.
// The Converter will then be used by the conversion endpoint for the type passed into NewWebhookManagedBy()
func (blder *WebhookBuilder[T]) WithConverter(converterConstructor func(*runtime.Scheme) (conversion.Converter, error)) *WebhookBuilder[T] {
	blder.converterConstructor = converterConstructor
	return blder
}

// WithLogConstructor overrides the webhook's LogConstructor.
func (blder *WebhookBuilder[T]) WithLogConstructor(logConstructor func(base logr.Logger, req *admission.Request) logr.Logger) *WebhookBuilder[T] {
	blder.logConstructor = logConstructor
	return blder
}

// WithContextFunc overrides the webhook's WithContextFunc.
func (blder *WebhookBuilder[T]) WithContextFunc(contextFunc func(context.Context, *http.Request) context.Context) *WebhookBuilder[T] {
	blder.contextFunc = contextFunc
	return blder
}

// RecoverPanic indicates whether panics caused by the webhook should be recovered.
// Defaults to true.
func (blder *WebhookBuilder[T]) RecoverPanic(recoverPanic bool) *WebhookBuilder[T] {
	blder.recoverPanic = &recoverPanic
	return blder
}

// WithCustomPath overrides the webhook's default path by the customPath
//
// Deprecated: WithCustomPath should not be used anymore.
// Please use WithValidatorCustomPath or WithDefaulterCustomPath instead.
func (blder *WebhookBuilder[T]) WithCustomPath(customPath string) *WebhookBuilder[T] {
	blder.customPath = customPath
	return blder
}

// WithValidatorCustomPath overrides the path of the Validator.
func (blder *WebhookBuilder[T]) WithValidatorCustomPath(customPath string) *WebhookBuilder[T] {
	blder.customValidatorCustomPath = customPath
	return blder
}

// WithDefaulterCustomPath overrides the path of the Defaulter.
func (blder *WebhookBuilder[T]) WithDefaulterCustomPath(customPath string) *WebhookBuilder[T] {
	blder.customDefaulterCustomPath = customPath
	return blder
}

// Complete builds the webhook.
func (blder *WebhookBuilder[T]) Complete() error {
	// Set the Config
	blder.loadRestConfig()

	// Configure the default LogConstructor
	blder.setLogConstructor()

	// Set the Webhook if needed
	return blder.registerWebhooks()
}

func (blder *WebhookBuilder[T]) loadRestConfig() {
	if blder.config == nil {
		blder.config = blder.mgr.GetConfig()
	}
}

func (blder *WebhookBuilder[T]) setLogConstructor() {
	if blder.logConstructor == nil {
		blder.logConstructor = func(base logr.Logger, req *admission.Request) logr.Logger {
			log := base.WithValues(
				"webhookGroup", blder.gvk.Group,
				"webhookKind", blder.gvk.Kind,
			)
			if req != nil {
				return log.WithValues(
					blder.gvk.Kind, klog.KRef(req.Namespace, req.Name),
					"namespace", req.Namespace, "name", req.Name,
					"resource", req.Resource, "user", req.UserInfo.Username,
					"requestID", req.UID,
				)
			}
			return log
		}
	}
}

func (blder *WebhookBuilder[T]) isThereCustomPathConflict() bool {
	return (blder.customPath != "" && blder.customDefaulter != nil && blder.customValidator != nil) || (blder.customPath != "" && blder.customDefaulterCustomPath != "") || (blder.customPath != "" && blder.customValidatorCustomPath != "")
}

func (blder *WebhookBuilder[T]) registerWebhooks() error {
	typ, err := blder.getType()
	if err != nil {
		return err
	}

	blder.gvk, err = apiutil.GVKForObject(typ, blder.mgr.GetScheme())
	if err != nil {
		return err
	}

	if blder.isThereCustomPathConflict() {
		return errors.New("only one of CustomDefaulter or CustomValidator should be set when using WithCustomPath. Otherwise, WithDefaulterCustomPath() and WithValidatorCustomPath() should be used")
	}
	if blder.customPath != "" {
		// isThereCustomPathConflict() already checks for potential conflicts.
		// Since we are sure that only one of customDefaulter or customValidator will be used,
		// we can set both customDefaulterCustomPath and validatingCustomPath.
		blder.customDefaulterCustomPath = blder.customPath
		blder.customValidatorCustomPath = blder.customPath
	}

	// Register webhook(s) for type
	err = blder.registerDefaultingWebhook()
	if err != nil {
		return err
	}

	err = blder.registerValidatingWebhook()
	if err != nil {
		return err
	}

	err = blder.registerConversionWebhook()
	if err != nil {
		return err
	}
	return blder.err
}

// registerDefaultingWebhook registers a defaulting webhook if necessary.
func (blder *WebhookBuilder[T]) registerDefaultingWebhook() error {
	mwh, err := blder.getDefaultingWebhook()
	if err != nil {
		return err
	}
	if mwh != nil {
		mwh.LogConstructor = blder.logConstructor
		mwh.WithContextFunc = blder.contextFunc
		path := generateMutatePath(blder.gvk)
		if blder.customDefaulterCustomPath != "" {
			generatedCustomPath, err := generateCustomPath(blder.customDefaulterCustomPath)
			if err != nil {
				return err
			}
			path = generatedCustomPath
		}

		// Checking if the path is already registered.
		// If so, just skip it.
		if !blder.isAlreadyHandled(path) {
			log.Info("Registering a mutating webhook",
				"GVK", blder.gvk,
				"path", path)
			blder.mgr.GetWebhookServer().Register(path, mwh)
		}
	}

	return nil
}

func (blder *WebhookBuilder[T]) getDefaultingWebhook() (*admission.Webhook, error) {
	var w *admission.Webhook
	if blder.defaulter != nil {
		if blder.customDefaulter != nil {
			return nil, errors.New("only one of Defaulter or CustomDefaulter can be set")
		}
		w = admission.WithDefaulter(blder.mgr.GetScheme(), blder.defaulter, blder.customDefaulterOpts...)
	} else if blder.customDefaulter != nil {
		w = admission.WithCustomDefaulter(blder.mgr.GetScheme(), blder.apiType, blder.customDefaulter, blder.customDefaulterOpts...)
	}
	if w != nil && blder.recoverPanic != nil {
		w = w.WithRecoverPanic(*blder.recoverPanic)
	}
	return w, nil
}

// registerValidatingWebhook registers a validating webhook if necessary.
func (blder *WebhookBuilder[T]) registerValidatingWebhook() error {
	vwh, err := blder.getValidatingWebhook()
	if err != nil {
		return err
	}
	if vwh != nil {
		vwh.LogConstructor = blder.logConstructor
		vwh.WithContextFunc = blder.contextFunc
		path := generateValidatePath(blder.gvk)
		if blder.customValidatorCustomPath != "" {
			generatedCustomPath, err := generateCustomPath(blder.customValidatorCustomPath)
			if err != nil {
				return err
			}
			path = generatedCustomPath
		}

		// Checking if the path is already registered.
		// If so, just skip it.
		if !blder.isAlreadyHandled(path) {
			log.Info("Registering a validating webhook",
				"GVK", blder.gvk,
				"path", path)
			blder.mgr.GetWebhookServer().Register(path, vwh)
		}
	}

	return nil
}

func (blder *WebhookBuilder[T]) getValidatingWebhook() (*admission.Webhook, error) {
	var w *admission.Webhook
	if blder.validator != nil {
		if blder.customValidator != nil {
			return nil, errors.New("only one of Validator or CustomValidator can be set")
		}
		w = admission.WithValidator(blder.mgr.GetScheme(), blder.validator)
	} else if blder.customValidator != nil {
		//nolint:staticcheck
		w = admission.WithCustomValidator(blder.mgr.GetScheme(), blder.apiType, blder.customValidator)
	}
	if w != nil && blder.recoverPanic != nil {
		w = w.WithRecoverPanic(*blder.recoverPanic)
	}
	return w, nil
}

func (blder *WebhookBuilder[T]) registerConversionWebhook() error {
	if blder.converterConstructor != nil {
		converter, err := blder.converterConstructor(blder.mgr.GetScheme())
		if err != nil {
			return err
		}

		if err := blder.mgr.GetConverterRegistry().RegisterConverter(blder.gvk.GroupKind(), converter); err != nil {
			return err
		}
	} else {
		ok, err := conversion.IsConvertible(blder.mgr.GetScheme(), blder.apiType)
		if err != nil {
			log.Error(err, "conversion check failed", "GVK", blder.gvk)
			return err
		}
		if !ok {
			return nil
		}
	}

	if !blder.isAlreadyHandled("/convert") {
		blder.mgr.GetWebhookServer().Register("/convert", conversion.NewWebhookHandler(blder.mgr.GetScheme(), blder.mgr.GetConverterRegistry()))
	}
	log.Info("Conversion webhook enabled", "GVK", blder.gvk)

	return nil
}

func (blder *WebhookBuilder[T]) getType() (runtime.Object, error) {
	if blder.apiType != nil {
		return blder.apiType, nil
	}
	return nil, errors.New("NewWebhookManagedBy() must be called with a valid object")
}

func (blder *WebhookBuilder[T]) isAlreadyHandled(path string) bool {
	if blder.mgr.GetWebhookServer().WebhookMux() == nil {
		return false
	}
	h, p := blder.mgr.GetWebhookServer().WebhookMux().Handler(&http.Request{URL: &url.URL{Path: path}})
	if p == path && h != nil {
		return true
	}
	return false
}

func generateMutatePath(gvk schema.GroupVersionKind) string {
	return "/mutate-" + strings.ReplaceAll(gvk.Group, ".", "-") + "-" +
		gvk.Version + "-" + strings.ToLower(gvk.Kind)
}

func generateValidatePath(gvk schema.GroupVersionKind) string {
	return "/validate-" + strings.ReplaceAll(gvk.Group, ".", "-") + "-" +
		gvk.Version + "-" + strings.ToLower(gvk.Kind)
}

const webhookPathStringValidation = `^((/[a-zA-Z0-9-_]+)+|/)$`

var validWebhookPathRegex = regexp.MustCompile(webhookPathStringValidation)

func generateCustomPath(customPath string) (string, error) {
	if !validWebhookPathRegex.MatchString(customPath) {
		return "", errors.New("customPath \"" + customPath + "\" does not match this regex: " + webhookPathStringValidation)
	}
	return customPath, nil
}
