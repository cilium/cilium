/*
Copyright 2017 The Kubernetes Authors.

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

package fake

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	certificates "k8s.io/kubernetes/pkg/apis/certificates"
)

// FakeCertificateSigningRequests implements CertificateSigningRequestInterface
type FakeCertificateSigningRequests struct {
	Fake *FakeCertificates
}

var certificatesigningrequestsResource = schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "", Resource: "certificatesigningrequests"}

var certificatesigningrequestsKind = schema.GroupVersionKind{Group: "certificates.k8s.io", Version: "", Kind: "CertificateSigningRequest"}

// Get takes name of the certificateSigningRequest, and returns the corresponding certificateSigningRequest object, and an error if there is any.
func (c *FakeCertificateSigningRequests) Get(name string, options v1.GetOptions) (result *certificates.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(certificatesigningrequestsResource, name), &certificates.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*certificates.CertificateSigningRequest), err
}

// List takes label and field selectors, and returns the list of CertificateSigningRequests that match those selectors.
func (c *FakeCertificateSigningRequests) List(opts v1.ListOptions) (result *certificates.CertificateSigningRequestList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(certificatesigningrequestsResource, certificatesigningrequestsKind, opts), &certificates.CertificateSigningRequestList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &certificates.CertificateSigningRequestList{}
	for _, item := range obj.(*certificates.CertificateSigningRequestList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested certificateSigningRequests.
func (c *FakeCertificateSigningRequests) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(certificatesigningrequestsResource, opts))
}

// Create takes the representation of a certificateSigningRequest and creates it.  Returns the server's representation of the certificateSigningRequest, and an error, if there is any.
func (c *FakeCertificateSigningRequests) Create(certificateSigningRequest *certificates.CertificateSigningRequest) (result *certificates.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(certificatesigningrequestsResource, certificateSigningRequest), &certificates.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*certificates.CertificateSigningRequest), err
}

// Update takes the representation of a certificateSigningRequest and updates it. Returns the server's representation of the certificateSigningRequest, and an error, if there is any.
func (c *FakeCertificateSigningRequests) Update(certificateSigningRequest *certificates.CertificateSigningRequest) (result *certificates.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(certificatesigningrequestsResource, certificateSigningRequest), &certificates.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*certificates.CertificateSigningRequest), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCertificateSigningRequests) UpdateStatus(certificateSigningRequest *certificates.CertificateSigningRequest) (*certificates.CertificateSigningRequest, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(certificatesigningrequestsResource, "status", certificateSigningRequest), &certificates.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*certificates.CertificateSigningRequest), err
}

// Delete takes name of the certificateSigningRequest and deletes it. Returns an error if one occurs.
func (c *FakeCertificateSigningRequests) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(certificatesigningrequestsResource, name), &certificates.CertificateSigningRequest{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCertificateSigningRequests) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(certificatesigningrequestsResource, listOptions)

	_, err := c.Fake.Invokes(action, &certificates.CertificateSigningRequestList{})
	return err
}

// Patch applies the patch and returns the patched certificateSigningRequest.
func (c *FakeCertificateSigningRequests) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *certificates.CertificateSigningRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(certificatesigningrequestsResource, name, data, subresources...), &certificates.CertificateSigningRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*certificates.CertificateSigningRequest), err
}
