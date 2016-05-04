package types

import (
	"strconv"

	"github.com/noironetworks/cilium-net/bpf/policymap"
)

type Consumer struct {
	ID           uint32
	Reverse      *Consumer
	DeletionMark bool
	Decision     ConsumableDecision
}

func NewConsumer(id uint32) *Consumer {
	return &Consumer{ID: id, Decision: ACCEPT}
}

type Consumable struct {
	ID           uint32                       `json:"id"`
	Iteration    int                          `json:"-"`
	Labels       *SecCtxLabel                 `json:"labels"`
	LabelList    []Label                      `json:"-"`
	Maps         map[int]*policymap.PolicyMap `json:"-"`
	Consumers    map[string]*Consumer         `json:"consumers"`
	ReverseRules map[uint32]*Consumer         `json:"-"`
}

func newConsumable(id uint32, labels *SecCtxLabel) *Consumable {
	consumable := &Consumable{
		ID:           id,
		Iteration:    0,
		Labels:       labels,
		Maps:         map[int]*policymap.PolicyMap{},
		Consumers:    map[string]*Consumer{},
		ReverseRules: map[uint32]*Consumer{},
	}

	if labels != nil {
		consumable.LabelList = make([]Label, len(labels.Labels))
		idx := 0
		for k, v := range labels.Labels {
			consumable.LabelList[idx] = Label{
				Key:    k,
				Value:  v.Value,
				Source: v.Source,
			}
			idx++
		}
	}

	return consumable
}

var consumableCache = map[uint32]*Consumable{}

func GetConsumable(id uint32, labels *SecCtxLabel) *Consumable {
	if v, ok := consumableCache[id]; ok {
		return v
	}

	consumableCache[id] = newConsumable(id, labels)

	return consumableCache[id]
}

func LookupConsumable(id uint32) *Consumable {
	v, _ := consumableCache[id]
	return v
}

func (c *Consumable) AddMap(m *policymap.PolicyMap) {
	// Check if map is already associated with this consumable
	if _, ok := c.Maps[m.Fd]; ok {
		return
	}

	log.Debugf("Adding map %v to consumable %v", m, c)
	c.Maps[m.Fd] = m

	// Populate the new map with the already established consumers of
	// this consumable
	for _, c := range c.Consumers {
		if err := m.AllowConsumer(c.ID); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	}
}

func deleteReverseRule(consumable, consumer uint32) {
	if reverse := LookupConsumable(consumable); reverse != nil {
		delete(reverse.ReverseRules, consumer)
		if reverse.wasLastRule(consumer) {
			reverse.removeFromMaps(consumer)
		}
	}
}

func (c *Consumable) Delete() {
	for _, consumer := range c.Consumers {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway
		if c.wasLastRule(consumer.ID) {
			c.removeFromMaps(consumer.ID)
		}

		deleteReverseRule(consumer.ID, c.ID)
	}

	delete(consumableCache, c.ID)
}

func (c *Consumable) RemoveMap(m *policymap.PolicyMap) {
	if m != nil {
		delete(c.Maps, m.Fd)
		log.Debugf("Removing map %v from consumable %v, new len %d", m, c, len(c.Maps))

		// If the last map of the consumable is gone the consumable is no longer
		// needed and should be removed from the cache and all cross references
		// must be undone.
		if len(c.Maps) == 0 {
			c.Delete()
		}
	}

}

func (c *Consumable) Consumer(id uint32) *Consumer {
	val, _ := c.Consumers[strconv.FormatUint(uint64(id), 10)]
	return val
}

func (c *Consumable) isNewRule(id uint32) bool {
	r1 := c.ReverseRules[id] != nil
	r2 := c.Consumers[strconv.FormatUint(uint64(id), 10)] != nil

	// golang has no XOR ... whaaa?
	return (r1 || r2) && !(r1 && r2)
}

func (c *Consumable) addToMaps(id uint32) {
	for _, m := range c.Maps {
		log.Debugf("Updating policy BPF map %s: allowing %d\n", m.String(), id)
		if err := m.AllowConsumer(id); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	}
}

func (c *Consumable) wasLastRule(id uint32) bool {
	return c.ReverseRules[id] == nil && c.Consumers[strconv.FormatUint(uint64(id), 10)] == nil
}

func (c *Consumable) removeFromMaps(id uint32) {
	for _, m := range c.Maps {
		log.Debugf("Updating policy BPF map %s: denying %d\n", m.String(), id)
		if err := m.DeleteConsumer(id); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	}
}

func (c *Consumable) AllowConsumer(id uint32) *Consumer {
	var consumer *Consumer

	if consumer = c.Consumer(id); consumer == nil {
		log.Debugf("New consumer %d for consumable %v", id, c)
		consumer = NewConsumer(id)
		c.Consumers[strconv.FormatUint(uint64(id), 10)] = consumer

		if c.isNewRule(id) {
			c.addToMaps(id)
		}
	} else {
		consumer.DeletionMark = false
	}

	return consumer
}

func (c *Consumable) AllowConsumerAndReverse(id uint32) {
	log.Debugf("Allowing direction %d -> %d\n", id, c.ID)
	fwd := c.AllowConsumer(id)

	if reverse := LookupConsumable(id); reverse != nil {
		log.Debugf("Allowing reverse direction %d -> %d\n", c.ID, id)
		if _, ok := reverse.ReverseRules[c.ID]; !ok {
			fwd.Reverse = NewConsumer(c.ID)
			reverse.ReverseRules[c.ID] = fwd.Reverse
			if reverse.isNewRule(c.ID) {
				reverse.addToMaps(c.ID)
			}
		}
	} else {
		log.Warningf("Allowed a consumer %d->%d which can't be found in the reverse direction", c.ID, id)
	}
}

func (c *Consumable) BanConsumer(id uint32) {
	n := strconv.FormatUint(uint64(id), 10)

	if consumer, ok := c.Consumers[n]; ok {
		log.Debugf("Removing consumer %v\n", consumer)
		delete(c.Consumers, n)
		if c.wasLastRule(id) {
			c.removeFromMaps(id)
		}

		if consumer.Reverse != nil {
			deleteReverseRule(id, c.ID)
		}
	}
}

func (c *Consumable) Allows(id uint32) bool {
	if consumer := c.Consumer(id); consumer != nil {
		if consumer.Decision == ACCEPT {
			return true
		}
	}

	return false
}
