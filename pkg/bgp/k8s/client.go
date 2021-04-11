// Copyright 2021 Authors of Cilium
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

// Package k8s provides a Kubernetes client to be used with MetalLB
// integration.
package k8s

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func New(l *logrus.Logger) *Client {
	return &Client{
		K8sClient: k8s.Client(),

		log: l,
	}
}

// Client wraps the K8s client so that it can conform to the client from
// MetalLB.
type Client struct {
	*k8s.K8sClient

	log *logrus.Logger
}

func (c *Client) Update(svc *v1.Service) (*v1.Service, error) {
	return c.CoreV1().Services(svc.GetNamespace()).Update(context.TODO(), svc, metav1.UpdateOptions{})
}
func (c *Client) UpdateStatus(svc *v1.Service) error {
	_, err := c.CoreV1().Services(svc.GetNamespace()).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
	return err
}

func (c *Client) Infof(_ *v1.Service, desc, fmt string, args ...interface{}) {
	c.log.WithField("event", desc).Infof(fmt, args...)
}
func (c *Client) Errorf(_ *v1.Service, desc, fmt string, args ...interface{}) {
	c.log.WithField("event", desc).Errorf(fmt, args...)
}
