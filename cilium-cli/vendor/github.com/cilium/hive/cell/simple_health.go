package cell

import (
	"sync"
)

type simpleHealthRoot struct {
	sync.Mutex
	all map[string]*SimpleHealth
}

type SimpleHealth struct {
	*simpleHealthRoot

	Scope  string
	Level  Level
	Status string
	Error  error
}

// NewScope implements cell.Health.
func (h *SimpleHealth) NewScope(name string) Health {
	h.Lock()
	defer h.Unlock()

	h2 := &SimpleHealth{
		simpleHealthRoot: h.simpleHealthRoot,
		Scope:            h.Scope + "." + name,
	}
	h.all[name] = h2
	return h2
}

func (h *SimpleHealth) GetChild(fullName string) *SimpleHealth {
	h.Lock()
	defer h.Unlock()

	if child, ok := h.all[fullName]; ok {
		return child
	}
	return nil
}

// Degraded implements cell.Health.
func (h *SimpleHealth) Degraded(reason string, err error) {
	h.Lock()
	defer h.Unlock()

	h.Level = StatusDegraded
	h.Status = reason
	h.Error = err
}

// OK implements cell.Health.
func (h *SimpleHealth) OK(status string) {
	h.Lock()
	defer h.Unlock()

	h.Level = StatusOK
	h.Status = status
	h.Error = nil
}

// Stopped implements cell.Health.
func (h *SimpleHealth) Stopped(reason string) {
	h.Lock()
	defer h.Unlock()

	h.Level = StatusStopped
	h.Status = reason
	h.Error = nil
}

func (h *SimpleHealth) Close() {
	h.Lock()
	defer h.Unlock()

	delete(h.all, h.Scope)
}

func NewSimpleHealth() (Health, *SimpleHealth) {
	h := &SimpleHealth{
		simpleHealthRoot: &simpleHealthRoot{
			all: make(map[string]*SimpleHealth),
		},
	}
	return h, h
}

var _ Health = &SimpleHealth{}

var SimpleHealthCell = Provide(NewSimpleHealth)
