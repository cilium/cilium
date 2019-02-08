/*
   Copyright The containerd Authors.

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

package containerd

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	contentapi "github.com/containerd/containerd/api/services/content/v1"
	diffapi "github.com/containerd/containerd/api/services/diff/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	leasesapi "github.com/containerd/containerd/api/services/leases/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/api/services/tasks/v1"
	versionservice "github.com/containerd/containerd/api/services/version/v1"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	contentproxy "github.com/containerd/containerd/content/proxy"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/leases"
	leasesproxy "github.com/containerd/containerd/leases/proxy"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/dialer"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/containerd/containerd/remotes/docker/schema1"
	"github.com/containerd/containerd/snapshots"
	snproxy "github.com/containerd/containerd/snapshots/proxy"
	"github.com/containerd/typeurl"
	ptypes "github.com/gogo/protobuf/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func init() {
	const prefix = "types.containerd.io"
	// register TypeUrls for commonly marshaled external types
	major := strconv.Itoa(specs.VersionMajor)
	typeurl.Register(&specs.Spec{}, prefix, "opencontainers/runtime-spec", major, "Spec")
	typeurl.Register(&specs.Process{}, prefix, "opencontainers/runtime-spec", major, "Process")
	typeurl.Register(&specs.LinuxResources{}, prefix, "opencontainers/runtime-spec", major, "LinuxResources")
	typeurl.Register(&specs.WindowsResources{}, prefix, "opencontainers/runtime-spec", major, "WindowsResources")
}

// New returns a new containerd client that is connected to the containerd
// instance provided by address
func New(address string, opts ...ClientOpt) (*Client, error) {
	var copts clientOpts
	for _, o := range opts {
		if err := o(&copts); err != nil {
			return nil, err
		}
	}
	if copts.timeout == 0 {
		copts.timeout = 10 * time.Second
	}
	rt := fmt.Sprintf("%s.%s", plugin.RuntimePlugin, runtime.GOOS)
	if copts.defaultRuntime != "" {
		rt = copts.defaultRuntime
	}
	c := &Client{
		runtime: rt,
	}
	if copts.services != nil {
		c.services = *copts.services
	}
	if address != "" {
		gopts := []grpc.DialOption{
			grpc.WithBlock(),
			grpc.WithInsecure(),
			grpc.FailOnNonTempDialError(true),
			grpc.WithBackoffMaxDelay(3 * time.Second),
			grpc.WithDialer(dialer.Dialer),

			// TODO(stevvooe): We may need to allow configuration of this on the client.
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaults.DefaultMaxRecvMsgSize)),
			grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(defaults.DefaultMaxSendMsgSize)),
		}
		if len(copts.dialOptions) > 0 {
			gopts = copts.dialOptions
		}
		if copts.defaultns != "" {
			unary, stream := newNSInterceptors(copts.defaultns)
			gopts = append(gopts,
				grpc.WithUnaryInterceptor(unary),
				grpc.WithStreamInterceptor(stream),
			)
		}
		connector := func() (*grpc.ClientConn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), copts.timeout)
			defer cancel()
			conn, err := grpc.DialContext(ctx, dialer.DialAddress(address), gopts...)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to dial %q", address)
			}
			return conn, nil
		}
		conn, err := connector()
		if err != nil {
			return nil, err
		}
		c.conn, c.connector = conn, connector
	}
	if copts.services == nil && c.conn == nil {
		return nil, errors.New("no grpc connection or services is available")
	}
	return c, nil
}

// NewWithConn returns a new containerd client that is connected to the containerd
// instance provided by the connection
func NewWithConn(conn *grpc.ClientConn, opts ...ClientOpt) (*Client, error) {
	var copts clientOpts
	for _, o := range opts {
		if err := o(&copts); err != nil {
			return nil, err
		}
	}
	c := &Client{
		conn:    conn,
		runtime: fmt.Sprintf("%s.%s", plugin.RuntimePlugin, runtime.GOOS),
	}
	if copts.services != nil {
		c.services = *copts.services
	}
	return c, nil
}

// Client is the client to interact with containerd and its various services
// using a uniform interface
type Client struct {
	services
	connMu    sync.Mutex
	conn      *grpc.ClientConn
	runtime   string
	connector func() (*grpc.ClientConn, error)
}

// Reconnect re-establishes the GRPC connection to the containerd daemon
func (c *Client) Reconnect() error {
	if c.connector == nil {
		return errors.New("unable to reconnect to containerd, no connector available")
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.conn.Close()
	conn, err := c.connector()
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

// IsServing returns true if the client can successfully connect to the
// containerd daemon and the healthcheck service returns the SERVING
// response.
// This call will block if a transient error is encountered during
// connection. A timeout can be set in the context to ensure it returns
// early.
func (c *Client) IsServing(ctx context.Context) (bool, error) {
	c.connMu.Lock()
	if c.conn == nil {
		c.connMu.Unlock()
		return false, errors.New("no grpc connection available")
	}
	c.connMu.Unlock()
	r, err := c.HealthService().Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.FailFast(false))
	if err != nil {
		return false, err
	}
	return r.Status == grpc_health_v1.HealthCheckResponse_SERVING, nil
}

// Containers returns all containers created in containerd
func (c *Client) Containers(ctx context.Context, filters ...string) ([]Container, error) {
	r, err := c.ContainerService().List(ctx, filters...)
	if err != nil {
		return nil, err
	}
	var out []Container
	for _, container := range r {
		out = append(out, containerFromRecord(c, container))
	}
	return out, nil
}

// NewContainer will create a new container in container with the provided id
// the id must be unique within the namespace
func (c *Client) NewContainer(ctx context.Context, id string, opts ...NewContainerOpts) (Container, error) {
	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	container := containers.Container{
		ID: id,
		Runtime: containers.RuntimeInfo{
			Name: c.runtime,
		},
	}
	for _, o := range opts {
		if err := o(ctx, c, &container); err != nil {
			return nil, err
		}
	}
	r, err := c.ContainerService().Create(ctx, container)
	if err != nil {
		return nil, err
	}
	return containerFromRecord(c, r), nil
}

// LoadContainer loads an existing container from metadata
func (c *Client) LoadContainer(ctx context.Context, id string) (Container, error) {
	r, err := c.ContainerService().Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return containerFromRecord(c, r), nil
}

// RemoteContext is used to configure object resolutions and transfers with
// remote content stores and image providers.
type RemoteContext struct {
	// Resolver is used to resolve names to objects, fetchers, and pushers.
	// If no resolver is provided, defaults to Docker registry resolver.
	Resolver remotes.Resolver

	// PlatformMatcher is used to match the platforms for an image
	// operation and define the preference when a single match is required
	// from multiple platforms.
	PlatformMatcher platforms.MatchComparer

	// Unpack is done after an image is pulled to extract into a snapshotter.
	// If an image is not unpacked on pull, it can be unpacked any time
	// afterwards. Unpacking is required to run an image.
	Unpack bool

	// Snapshotter used for unpacking
	Snapshotter string

	// Labels to be applied to the created image
	Labels map[string]string

	// BaseHandlers are a set of handlers which get are called on dispatch.
	// These handlers always get called before any operation specific
	// handlers.
	BaseHandlers []images.Handler

	// ConvertSchema1 is whether to convert Docker registry schema 1
	// manifests. If this option is false then any image which resolves
	// to schema 1 will return an error since schema 1 is not supported.
	ConvertSchema1 bool

	// Platforms defines which platforms to handle when doing the image operation.
	// Platforms is ignored when a PlatformMatcher is set, otherwise the
	// platforms will be used to create a PlatformMatcher with no ordering
	// preference.
	Platforms []string
}

func defaultRemoteContext() *RemoteContext {
	return &RemoteContext{
		Resolver: docker.NewResolver(docker.ResolverOptions{
			Client: http.DefaultClient,
		}),
		Snapshotter: DefaultSnapshotter,
	}
}

// Fetch downloads the provided content into containerd's content store
// and returns a non-platform specific image reference
func (c *Client) Fetch(ctx context.Context, ref string, opts ...RemoteOpt) (images.Image, error) {
	fetchCtx := defaultRemoteContext()
	for _, o := range opts {
		if err := o(c, fetchCtx); err != nil {
			return images.Image{}, err
		}
	}

	if fetchCtx.Unpack {
		return images.Image{}, errors.New("unpack on fetch not supported, try pull")
	}

	if fetchCtx.PlatformMatcher == nil {
		if len(fetchCtx.Platforms) == 0 {
			fetchCtx.PlatformMatcher = platforms.All
		} else {
			var ps []ocispec.Platform
			for _, s := range fetchCtx.Platforms {
				p, err := platforms.Parse(s)
				if err != nil {
					return images.Image{}, errors.Wrapf(err, "invalid platform %s", s)
				}
				ps = append(ps, p)
			}

			fetchCtx.PlatformMatcher = platforms.Any(ps...)
		}
	}

	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return images.Image{}, err
	}
	defer done(ctx)

	return c.fetch(ctx, fetchCtx, ref, 0)
}

// Pull downloads the provided content into containerd's content store
// and returns a platform specific image object
func (c *Client) Pull(ctx context.Context, ref string, opts ...RemoteOpt) (Image, error) {
	pullCtx := defaultRemoteContext()
	for _, o := range opts {
		if err := o(c, pullCtx); err != nil {
			return nil, err
		}
	}

	if pullCtx.PlatformMatcher == nil {
		if len(pullCtx.Platforms) > 1 {
			return nil, errors.New("cannot pull multiplatform image locally, try Fetch")
		} else if len(pullCtx.Platforms) == 0 {
			pullCtx.PlatformMatcher = platforms.Default()
		} else {
			p, err := platforms.Parse(pullCtx.Platforms[0])
			if err != nil {
				return nil, errors.Wrapf(err, "invalid platform %s", pullCtx.Platforms[0])
			}

			pullCtx.PlatformMatcher = platforms.Only(p)
		}
	}

	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	img, err := c.fetch(ctx, pullCtx, ref, 1)
	if err != nil {
		return nil, err
	}

	i := NewImageWithPlatform(c, img, pullCtx.PlatformMatcher)

	if pullCtx.Unpack {
		if err := i.Unpack(ctx, pullCtx.Snapshotter); err != nil {
			return nil, errors.Wrapf(err, "failed to unpack image on snapshotter %s", pullCtx.Snapshotter)
		}
	}

	return i, nil
}

func (c *Client) fetch(ctx context.Context, rCtx *RemoteContext, ref string, limit int) (images.Image, error) {
	store := c.ContentStore()
	name, desc, err := rCtx.Resolver.Resolve(ctx, ref)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to resolve reference %q", ref)
	}

	fetcher, err := rCtx.Resolver.Fetcher(ctx, name)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to get fetcher for %q", name)
	}

	var (
		schema1Converter *schema1.Converter
		handler          images.Handler
	)
	if desc.MediaType == images.MediaTypeDockerSchema1Manifest && rCtx.ConvertSchema1 {
		schema1Converter = schema1.NewConverter(store, fetcher)
		handler = images.Handlers(append(rCtx.BaseHandlers, schema1Converter)...)
	} else {
		// Get all the children for a descriptor
		childrenHandler := images.ChildrenHandler(store)
		// Set any children labels for that content
		childrenHandler = images.SetChildrenLabels(store, childrenHandler)
		// Filter children by platforms
		childrenHandler = images.FilterPlatforms(childrenHandler, rCtx.PlatformMatcher)
		// Sort and limit manifests if a finite number is needed
		if limit > 0 {
			childrenHandler = images.LimitManifests(childrenHandler, rCtx.PlatformMatcher, limit)
		}

		handler = images.Handlers(append(rCtx.BaseHandlers,
			remotes.FetchHandler(store, fetcher),
			childrenHandler,
		)...)
	}

	if err := images.Dispatch(ctx, handler, desc); err != nil {
		return images.Image{}, err
	}
	if schema1Converter != nil {
		desc, err = schema1Converter.Convert(ctx)
		if err != nil {
			return images.Image{}, err
		}
	}

	img := images.Image{
		Name:   name,
		Target: desc,
		Labels: rCtx.Labels,
	}

	is := c.ImageService()
	for {
		if created, err := is.Create(ctx, img); err != nil {
			if !errdefs.IsAlreadyExists(err) {
				return images.Image{}, err
			}

			updated, err := is.Update(ctx, img)
			if err != nil {
				// if image was removed, try create again
				if errdefs.IsNotFound(err) {
					continue
				}
				return images.Image{}, err
			}

			img = updated
		} else {
			img = created
		}

		return img, nil
	}
}

// Push uploads the provided content to a remote resource
func (c *Client) Push(ctx context.Context, ref string, desc ocispec.Descriptor, opts ...RemoteOpt) error {
	pushCtx := defaultRemoteContext()
	for _, o := range opts {
		if err := o(c, pushCtx); err != nil {
			return err
		}
	}
	if pushCtx.PlatformMatcher == nil {
		if len(pushCtx.Platforms) > 0 {
			var ps []ocispec.Platform
			for _, platform := range pushCtx.Platforms {
				p, err := platforms.Parse(platform)
				if err != nil {
					return errors.Wrapf(err, "invalid platform %s", platform)
				}
				ps = append(ps, p)
			}
			pushCtx.PlatformMatcher = platforms.Any(ps...)
		} else {
			pushCtx.PlatformMatcher = platforms.All
		}
	}

	pusher, err := pushCtx.Resolver.Pusher(ctx, ref)
	if err != nil {
		return err
	}

	return remotes.PushContent(ctx, pusher, desc, c.ContentStore(), pushCtx.PlatformMatcher, pushCtx.BaseHandlers...)
}

// GetImage returns an existing image
func (c *Client) GetImage(ctx context.Context, ref string) (Image, error) {
	i, err := c.ImageService().Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	return NewImage(c, i), nil
}

// ListImages returns all existing images
func (c *Client) ListImages(ctx context.Context, filters ...string) ([]Image, error) {
	imgs, err := c.ImageService().List(ctx, filters...)
	if err != nil {
		return nil, err
	}
	images := make([]Image, len(imgs))
	for i, img := range imgs {
		images[i] = NewImage(c, img)
	}
	return images, nil
}

// Subscribe to events that match one or more of the provided filters.
//
// Callers should listen on both the envelope and errs channels. If the errs
// channel returns nil or an error, the subscriber should terminate.
//
// The subscriber can stop receiving events by canceling the provided context.
// The errs channel will be closed and return a nil error.
func (c *Client) Subscribe(ctx context.Context, filters ...string) (ch <-chan *events.Envelope, errs <-chan error) {
	return c.EventService().Subscribe(ctx, filters...)
}

// Close closes the clients connection to containerd
func (c *Client) Close() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// NamespaceService returns the underlying Namespaces Store
func (c *Client) NamespaceService() namespaces.Store {
	if c.namespaceStore != nil {
		return c.namespaceStore
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return NewNamespaceStoreFromClient(namespacesapi.NewNamespacesClient(c.conn))
}

// ContainerService returns the underlying container Store
func (c *Client) ContainerService() containers.Store {
	if c.containerStore != nil {
		return c.containerStore
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return NewRemoteContainerStore(containersapi.NewContainersClient(c.conn))
}

// ContentStore returns the underlying content Store
func (c *Client) ContentStore() content.Store {
	if c.contentStore != nil {
		return c.contentStore
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return contentproxy.NewContentStore(contentapi.NewContentClient(c.conn))
}

// SnapshotService returns the underlying snapshotter for the provided snapshotter name
func (c *Client) SnapshotService(snapshotterName string) snapshots.Snapshotter {
	if c.snapshotters != nil {
		return c.snapshotters[snapshotterName]
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return snproxy.NewSnapshotter(snapshotsapi.NewSnapshotsClient(c.conn), snapshotterName)
}

// TaskService returns the underlying TasksClient
func (c *Client) TaskService() tasks.TasksClient {
	if c.taskService != nil {
		return c.taskService
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return tasks.NewTasksClient(c.conn)
}

// ImageService returns the underlying image Store
func (c *Client) ImageService() images.Store {
	if c.imageStore != nil {
		return c.imageStore
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return NewImageStoreFromClient(imagesapi.NewImagesClient(c.conn))
}

// DiffService returns the underlying Differ
func (c *Client) DiffService() DiffService {
	if c.diffService != nil {
		return c.diffService
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return NewDiffServiceFromClient(diffapi.NewDiffClient(c.conn))
}

// IntrospectionService returns the underlying Introspection Client
func (c *Client) IntrospectionService() introspectionapi.IntrospectionClient {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return introspectionapi.NewIntrospectionClient(c.conn)
}

// LeasesService returns the underlying Leases Client
func (c *Client) LeasesService() leases.Manager {
	if c.leasesService != nil {
		return c.leasesService
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return leasesproxy.NewLeaseManager(leasesapi.NewLeasesClient(c.conn))
}

// HealthService returns the underlying GRPC HealthClient
func (c *Client) HealthService() grpc_health_v1.HealthClient {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return grpc_health_v1.NewHealthClient(c.conn)
}

// EventService returns the underlying event service
func (c *Client) EventService() EventService {
	if c.eventService != nil {
		return c.eventService
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return NewEventServiceFromClient(eventsapi.NewEventsClient(c.conn))
}

// VersionService returns the underlying VersionClient
func (c *Client) VersionService() versionservice.VersionClient {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return versionservice.NewVersionClient(c.conn)
}

// Version of containerd
type Version struct {
	// Version number
	Version string
	// Revision from git that was built
	Revision string
}

// Version returns the version of containerd that the client is connected to
func (c *Client) Version(ctx context.Context) (Version, error) {
	c.connMu.Lock()
	if c.conn == nil {
		c.connMu.Unlock()
		return Version{}, errors.New("no grpc connection available")
	}
	c.connMu.Unlock()
	response, err := c.VersionService().Version(ctx, &ptypes.Empty{})
	if err != nil {
		return Version{}, err
	}
	return Version{
		Version:  response.Version,
		Revision: response.Revision,
	}, nil
}
