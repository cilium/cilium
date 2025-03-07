// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package portforward

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	kutil "k8s.io/kubectl/pkg/util"
	"k8s.io/kubectl/pkg/util/podutils"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

// ForwardedPort holds the local and remote mapped ports.
type ForwardedPort struct {
	Local  uint16
	Remote uint16
}

// PortForwardParameters are the needed parameters to call PortForward.
//
// Ports value follow the kubectl syntax: <local-port>:<remote-port>:
//   - 5000 means 5000:5000 listening on 5000 port locally, forwarding to 5000 in the pod
//   - 8888:5000 means listening on 8888 port locally, forwarding to 5000 in the pod
//   - 0:5000 means listening on a random port locally, forwarding to 5000 in the pod
//   - :5000 means listening on a random port locally, forwarding to 5000 in the pod
type PortForwardParameters struct {
	Namespace  string
	Pod        string
	Ports      []string
	Addresses  []string
	OutWriters OutWriters
}

// OutWriters holds the two io.Writer used by the port forward.
// These can be safely disabled by setting them to nil.
type OutWriters struct {
	Out    io.Writer
	ErrOut io.Writer
}

// PortForwarder augments the k8s client-go PortForwarder with helper methods using a clientset.
type PortForwarder struct {
	clientset kubernetes.Interface
	config    *rest.Config
}

// NewPortForwarder creates a new PortForwarder ready to use.
func NewPortForwarder(clientset kubernetes.Interface, config *rest.Config) *PortForwarder {
	return &PortForwarder{clientset: clientset, config: config}
}

// PortForwardResult are the ports that have been forwarded by PortForward.
type PortForwardResult struct {
	ForwardedPorts []ForwardedPort
}

// PortForward executes in a goroutine a port forward command.
// To stop the port-forwarding, use the context by cancelling it.
func (pf *PortForwarder) PortForward(ctx context.Context, p PortForwardParameters) (*PortForwardResult, error) {
	req := pf.clientset.CoreV1().RESTClient().Post().Namespace(p.Namespace).
		Resource("pods").Name(p.Pod).SubResource(strings.ToLower("PortForward"))

	roundTripper, upgrader, err := spdy.RoundTripperFor(pf.config)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, req.URL())
	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{}, 1)
	if len(p.Addresses) == 0 {
		p.Addresses = []string{"localhost"}
	}

	pw, err := portforward.NewOnAddresses(dialer, p.Addresses, p.Ports, stopChan, readyChan, p.OutWriters.Out, p.OutWriters.ErrOut)
	if err != nil {
		return nil, err
	}

	errChan := make(chan error, 1)
	go func() {
		if err := pw.ForwardPorts(); err != nil {
			errChan <- err
		}
	}()

	go func() {
		<-ctx.Done()
		close(stopChan)
	}()

	select {
	case <-pw.Ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, err
	}

	ports, err := pw.GetPorts()
	if err != nil {
		return nil, err
	}

	forwardedPorts := make([]ForwardedPort, 0, len(ports))
	for _, port := range ports {
		forwardedPorts = append(forwardedPorts, ForwardedPort{port.Local, port.Remote})
	}

	return &PortForwardResult{
		ForwardedPorts: forwardedPorts,
	}, nil
}

// PortForwardServiceResult are the ports that have been forwarded by PortForwardService.
type PortForwardServiceResult struct {
	ForwardedPort ForwardedPort
}

// PortForwardService executes in a goroutine a port forward command towards one of the pod behind a
// service. If `localPort` is 0, a random port is selected. If `svcPort` is 0, uses the first port
// configured on the service.
//
// To stop the port-forwarding, use the context by cancelling it.
func (pf *PortForwarder) PortForwardService(ctx context.Context, namespace, name string, localPort, svcPort int32) (*PortForwardServiceResult, error) {
	svc, err := pf.clientset.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get service %q: %w", name, err)
	}

	pod, err := pf.getFirstPodForService(ctx, svc)
	if err != nil {
		return nil, fmt.Errorf("failed to get service %q: %w", name, err)
	}

	if svcPort == 0 {
		svcPort = svc.Spec.Ports[0].Port
	}

	containerPort, err := kutil.LookupContainerPortNumberByServicePort(*svc, *pod, svcPort)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup container port with service port %d: %w", svcPort, err)
	}

	p := PortForwardParameters{
		Namespace:  pod.Namespace,
		Pod:        pod.Name,
		Ports:      []string{fmt.Sprintf("%d:%d", localPort, containerPort)},
		Addresses:  nil, // default is localhost
		OutWriters: OutWriters{Out: nil, ErrOut: nil},
	}

	res, err := pf.PortForward(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("failed to port forward: %w", err)
	}

	return &PortForwardServiceResult{
		ForwardedPort: res.ForwardedPorts[0],
	}, nil
}

// getFirstPodForService returns the first pod in the list of pods matching the service selector,
// sorted from most to less active (see `podutils.ActivePods` for more details).
func (pf *PortForwarder) getFirstPodForService(ctx context.Context, svc *corev1.Service) (*corev1.Pod, error) {
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	podList, err := pf.clientset.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("failed to get list of pods for service %q: %w", svc.Name, err)
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no pods found for service: %s", svc.Name)
	}
	if len(podList.Items) == 1 {
		return &podList.Items[0], nil
	}

	pods := make([]*corev1.Pod, 0, len(podList.Items))
	for _, pod := range podList.Items {
		pods = append(pods, &pod)
	}
	sortBy := func(pods []*corev1.Pod) sort.Interface { return sort.Reverse(podutils.ActivePods(pods)) }
	sort.Sort(sortBy(pods))

	return pods[0], nil
}
