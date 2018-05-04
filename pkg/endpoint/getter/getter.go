package getter

// EndpointGetter should be implemented by Endpoint so you don't
// have to use pkg/endpoint if you only want to read Endpoint data in other package
type EndpointGetter interface {
	GetID() uint64
	GetLabels() []string
}
