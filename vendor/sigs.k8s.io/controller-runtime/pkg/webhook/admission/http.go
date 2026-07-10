/*
Copyright 2018 The Kubernetes Authors.

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

package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	v1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var admissionScheme = runtime.NewScheme()
var admissionCodecs = serializer.NewCodecFactory(admissionScheme)

// adapted from https://github.com/kubernetes/kubernetes/blob/c28c2009181fcc44c5f6b47e10e62dacf53e4da0/staging/src/k8s.io/pod-security-admission/cmd/webhook/server/server.go
//
// From https://github.com/kubernetes/apiserver/blob/d6876a0600de06fef75968c4641c64d7da499f25/pkg/server/config.go#L433-L442C5:
//
//	     1.5MB is the recommended client request size in byte
//		 the etcd server should accept. See
//		 https://github.com/etcd-io/etcd/blob/release-3.4/embed/config.go#L56.
//		 A request body might be encoded in json, and is converted to
//		 proto when persisted in etcd, so we allow 2x as the largest request
//		 body size to be accepted and decoded in a write request.
//
// For the admission request, we can infer that it contains at most two objects
// (the old and new versions of the object being admitted), each of which can
// be at most 3MB in size. For the rest of the request, we can assume that
// it will be less than 1MB in size. Therefore, we can set the max request
// size to 7MB.
// If your use case requires larger max request sizes, please
// open an issue (https://github.com/kubernetes-sigs/controller-runtime/issues/new).
const maxRequestSize = int64(7 * 1024 * 1024)

func init() {
	utilruntime.Must(v1.AddToScheme(admissionScheme))
	utilruntime.Must(v1beta1.AddToScheme(admissionScheme))
}

var _ http.Handler = &Webhook{}

func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if wh.WithContextFunc != nil {
		ctx = wh.WithContextFunc(ctx, r)
	}

	if r.Body == nil || r.Body == http.NoBody {
		err := errors.New("request body is empty")
		wh.getLogger(nil).Error(err, "bad request")
		wh.writeResponse(w, Errored(http.StatusBadRequest, err))
		return
	}

	defer r.Body.Close()
	limitedReader := &io.LimitedReader{R: r.Body, N: maxRequestSize}
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		wh.getLogger(nil).Error(err, "unable to read the body from the incoming request")
		wh.writeResponse(w, Errored(http.StatusBadRequest, err))
		return
	}
	if limitedReader.N <= 0 {
		err := fmt.Errorf("request entity is too large; limit is %d bytes", maxRequestSize)
		wh.getLogger(nil).Error(err, "unable to read the body from the incoming request; limit reached")
		wh.writeResponse(w, Errored(http.StatusRequestEntityTooLarge, err))
		return
	}

	// verify the content type is accurate
	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		err = fmt.Errorf("contentType=%s, expected application/json", contentType)
		wh.getLogger(nil).Error(err, "unable to process a request with unknown content type")
		wh.writeResponse(w, Errored(http.StatusBadRequest, err))
		return
	}

	// Both v1 and v1beta1 AdmissionReview types are exactly the same, so the v1beta1 type can
	// be decoded into the v1 type. However the runtime codec's decoder guesses which type to
	// decode into by type name if an Object's TypeMeta isn't set. By setting TypeMeta of an
	// unregistered type to the v1 GVK, the decoder will coerce a v1beta1 AdmissionReview to v1.
	// The actual AdmissionReview GVK will be used to write a typed response in case the
	// webhook config permits multiple versions, otherwise this response will fail.
	req := Request{}
	ar := unversionedAdmissionReview{}
	// avoid an extra copy
	ar.Request = &req.AdmissionRequest
	ar.SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("AdmissionReview"))
	_, actualAdmRevGVK, err := admissionCodecs.UniversalDeserializer().Decode(body, nil, &ar)
	if err != nil {
		wh.getLogger(nil).Error(err, "unable to decode the request")
		wh.writeResponse(w, Errored(http.StatusBadRequest, err))
		return
	}
	wh.getLogger(&req).V(5).Info("received request")

	wh.writeResponseTyped(w, wh.Handle(ctx, req), actualAdmRevGVK)
}

// writeResponse writes response to w generically, i.e. without encoding GVK information.
func (wh *Webhook) writeResponse(w io.Writer, response Response) {
	wh.writeAdmissionResponse(w, v1.AdmissionReview{Response: &response.AdmissionResponse})
}

// writeResponseTyped writes response to w with GVK set to admRevGVK, which is necessary
// if multiple AdmissionReview versions are permitted by the webhook.
func (wh *Webhook) writeResponseTyped(w io.Writer, response Response, admRevGVK *schema.GroupVersionKind) {
	ar := v1.AdmissionReview{
		Response: &response.AdmissionResponse,
	}
	// Default to a v1 AdmissionReview, otherwise the API server may not recognize the request
	// if multiple AdmissionReview versions are permitted by the webhook config.
	// TODO(estroz): this should be configurable since older API servers won't know about v1.
	if admRevGVK == nil || *admRevGVK == (schema.GroupVersionKind{}) {
		ar.SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("AdmissionReview"))
	} else {
		ar.SetGroupVersionKind(*admRevGVK)
	}
	wh.writeAdmissionResponse(w, ar)
}

// writeAdmissionResponse writes ar to w.
func (wh *Webhook) writeAdmissionResponse(w io.Writer, ar v1.AdmissionReview) {
	if err := json.NewEncoder(w).Encode(ar); err != nil {
		wh.getLogger(nil).Error(err, "unable to encode and write the response")
		// Since the `ar v1.AdmissionReview` is a clear and legal object,
		// it should not have problem to be marshalled into bytes.
		// The error here is probably caused by the abnormal HTTP connection,
		// e.g., broken pipe, so we can only write the error response once,
		// to avoid endless circular calling.
		serverError := Errored(http.StatusInternalServerError, err)
		if err = json.NewEncoder(w).Encode(v1.AdmissionReview{Response: &serverError.AdmissionResponse}); err != nil {
			wh.getLogger(nil).Error(err, "still unable to encode and write the InternalServerError response")
		}
	} else {
		res := ar.Response
		if log := wh.getLogger(nil); log.V(5).Enabled() {
			if res.Result != nil {
				log = log.WithValues("code", res.Result.Code, "reason", res.Result.Reason, "message", res.Result.Message)
			}
			log.V(5).Info("wrote response", "requestID", res.UID, "allowed", res.Allowed)
		}
	}
}

// unversionedAdmissionReview is used to decode both v1 and v1beta1 AdmissionReview types.
type unversionedAdmissionReview struct {
	v1.AdmissionReview
}

var _ runtime.Object = &unversionedAdmissionReview{}
