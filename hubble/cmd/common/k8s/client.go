package k8s

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport/spdy"

	"github.com/cilium/cilium/pkg/safeio"
)

// Slim version of: https://github.com/cilium/cilium/tree/v1.17.0-pre.1/cilium-cli/k8s/client.go
type Client struct {
	Clientset kubernetes.Interface
	Config    *rest.Config
}

func NewClient(contextName, kubeconfig string) (*Client, error) {
	restClientGetter := genericclioptions.ConfigFlags{
		Context:    &contextName,
		KubeConfig: &kubeconfig,
	}
	rawKubeConfigLoader := restClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{
		Clientset: clientset,
		Config:    config,
	}, nil
}

func (c *Client) GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error) {
	return c.Clientset.CoreV1().Services(namespace).Get(ctx, name, opts)
}

// TODO: Consider replacing kubectl-based port-forwarding with native impl using k8s client
func (c *Client) ProxyTCP(ctx context.Context, namespace, name string, port uint16, handler func(io.ReadWriteCloser) error) error {
	request := c.Clientset.CoreV1().RESTClient().Post().
		Resource(corev1.ResourcePods.String()).
		Namespace(namespace).
		Name(name).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(c.Config)
	if err != nil {
		return fmt.Errorf("creating round tripper: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, request.URL())

	const portForwardProtocolV1Name = "portforward.k8s.io"
	conn, proto, err := dialer.Dial(portForwardProtocolV1Name)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}

	defer conn.Close()
	if proto != portForwardProtocolV1Name {
		return fmt.Errorf("unable to negotiate protocol: client supports %q, server returned %q", portForwardProtocolV1Name, proto)
	}

	go func() {
		select {
		case <-ctx.Done():
			// Close aborts all remaining streams, and unblocks read operations.
			conn.Close()
		case <-conn.CloseChan():
		}
	}()

	return stream(conn, port, handler)
}

// The following is an adapted version of part of the client-go's port-forward connection handling implementation:
// https://github.com/kubernetes/client-go/blob/4ebe42d8c9c18f464fcc7b4f15b3a632db4cbdb2/tools/portforward/portforward.go#L335-L416
func stream(conn httpstream.Connection, port uint16, handler func(io.ReadWriteCloser) error) error {
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.FormatUint(uint64(port), 10))

	errorStream, err := conn.CreateStream(headers)
	if err != nil {
		return fmt.Errorf("creating error stream: %w", err)
	}
	// we're not writing to this stream
	errorStream.Close()
	defer conn.RemoveStreams(errorStream)

	errorDone := make(chan error)
	go func() {
		defer close(errorDone)
		message, err := safeio.ReadAllLimit(errorStream, safeio.KB)
		switch {
		case err != nil:
			errorDone <- fmt.Errorf("reading from error stream: %w", err)
		case len(message) > 0:
			errorDone <- errors.New(string(message))
		}
	}()

	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := conn.CreateStream(headers)
	if err != nil {
		return fmt.Errorf("creating data stream: %w", err)
	}
	defer conn.RemoveStreams(dataStream)

	dataDone := make(chan error)
	go func() {
		defer close(dataDone)
		if err := handler(dataStream); err != nil {
			dataDone <- err
		}
	}()

	// Wait for both goroutines to terminate
	err = <-dataDone
	if err2 := <-errorDone; err2 != nil {
		err = err2
	}

	return err
}
