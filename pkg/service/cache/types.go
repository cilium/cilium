package cache

// Used to implement the topology aware hints.
const LabelTopologyZone = "topology.kubernetes.io/zone"

// CacheAction is the type of action that was performed on the cache
type CacheAction int

const (
	// UpdateService reflects that the service was updated or added
	UpdateService CacheAction = iota

	// DeleteService reflects that the service was deleted
	DeleteService

	// Synchronized reflects that the cache has synchronized with upstream
	// resources. All fields except 'Action' are left uninitialized in
	// ServiceEvent.
	Synchronized
)

// String returns the cache action as a string
func (c CacheAction) String() string {
	switch c {
	case UpdateService:
		return "service-updated"
	case DeleteService:
		return "service-deleted"
	case Synchronized:
		return "synchronized"
	default:
		return "unknown"
	}
}

// ServiceEvent is emitted to observers of ServiceCache and describes
// the change that occurred in the cache
type ServiceEvent struct {
	// Action is the action that was performed in the cache
	Action CacheAction

	// ID is the identified of the service
	ID ServiceID

	// Service is the service structure
	Service *Service

	// OldService is the service structure
	OldService *Service

	// Endpoints is the endpoints structured correlated with the service
	Endpoints *Endpoints
}
