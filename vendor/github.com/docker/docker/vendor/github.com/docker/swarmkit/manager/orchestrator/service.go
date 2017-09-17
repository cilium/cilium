package orchestrator

import (
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/log"
	"github.com/docker/swarmkit/manager/state/store"
	"golang.org/x/net/context"
)

// IsReplicatedService checks if a service is a replicated service.
func IsReplicatedService(service *api.Service) bool {
	// service nil validation is required as there are scenarios
	// where service is removed from store
	if service == nil {
		return false
	}
	_, ok := service.Spec.GetMode().(*api.ServiceSpec_Replicated)
	return ok
}

// IsGlobalService checks if the service is a global service.
func IsGlobalService(service *api.Service) bool {
	if service == nil {
		return false
	}
	_, ok := service.Spec.GetMode().(*api.ServiceSpec_Global)
	return ok
}

// DeleteServiceTasks deletes the tasks associated with a service.
func DeleteServiceTasks(ctx context.Context, s *store.MemoryStore, service *api.Service) {
	var (
		tasks []*api.Task
		err   error
	)
	s.View(func(tx store.ReadTx) {
		tasks, err = store.FindTasks(tx, store.ByServiceID(service.ID))
	})
	if err != nil {
		log.G(ctx).WithError(err).Errorf("failed to list tasks")
		return
	}

	err = s.Batch(func(batch *store.Batch) error {
		for _, t := range tasks {
			err := batch.Update(func(tx store.Tx) error {
				if err := store.DeleteTask(tx, t.ID); err != nil {
					log.G(ctx).WithError(err).Errorf("failed to delete task")
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.G(ctx).WithError(err).Errorf("task search transaction failed")
	}
}
