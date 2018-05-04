package getter

type EndpointGetter interface {
	GetID() uint64
	GetLabels() []string
}
