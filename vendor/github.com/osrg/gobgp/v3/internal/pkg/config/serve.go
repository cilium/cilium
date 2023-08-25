package config

import (
	"github.com/spf13/viper"

	"github.com/osrg/gobgp/v3/pkg/log"
)

type BgpConfigSet struct {
	Global            Global             `mapstructure:"global"`
	Neighbors         []Neighbor         `mapstructure:"neighbors"`
	PeerGroups        []PeerGroup        `mapstructure:"peer-groups"`
	RpkiServers       []RpkiServer       `mapstructure:"rpki-servers"`
	BmpServers        []BmpServer        `mapstructure:"bmp-servers"`
	Vrfs              []Vrf              `mapstructure:"vrfs"`
	MrtDump           []Mrt              `mapstructure:"mrt-dump"`
	Zebra             Zebra              `mapstructure:"zebra"`
	Collector         Collector          `mapstructure:"collector"`
	DefinedSets       DefinedSets        `mapstructure:"defined-sets"`
	PolicyDefinitions []PolicyDefinition `mapstructure:"policy-definitions"`
	DynamicNeighbors  []DynamicNeighbor  `mapstructure:"dynamic-neighbors"`
}

func ReadConfigfile(path, format string) (*BgpConfigSet, error) {
	// Update config file type, if detectable
	format = detectConfigFileType(path, format)

	config := &BgpConfigSet{}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType(format)
	var err error
	if err = v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err = v.UnmarshalExact(config); err != nil {
		return nil, err
	}
	if err = setDefaultConfigValuesWithViper(v, config); err != nil {
		return nil, err
	}
	return config, nil
}

func ConfigSetToRoutingPolicy(c *BgpConfigSet) *RoutingPolicy {
	return &RoutingPolicy{
		DefinedSets:       c.DefinedSets,
		PolicyDefinitions: c.PolicyDefinitions,
	}
}

func UpdatePeerGroupConfig(logger log.Logger, curC, newC *BgpConfigSet) ([]PeerGroup, []PeerGroup, []PeerGroup) {
	addedPg := []PeerGroup{}
	deletedPg := []PeerGroup{}
	updatedPg := []PeerGroup{}

	for _, n := range newC.PeerGroups {
		if idx := existPeerGroup(n.Config.PeerGroupName, curC.PeerGroups); idx < 0 {
			addedPg = append(addedPg, n)
		} else if !n.Equal(&curC.PeerGroups[idx]) {
			logger.Debug("Current peer-group config",
				log.Fields{
					"Topic": "Config",
					"Key":   curC.PeerGroups[idx]})
			logger.Debug("New peer-group config",
				log.Fields{
					"Topic": "Config",
					"Key":   n})
			updatedPg = append(updatedPg, n)
		}
	}

	for _, n := range curC.PeerGroups {
		if existPeerGroup(n.Config.PeerGroupName, newC.PeerGroups) < 0 {
			deletedPg = append(deletedPg, n)
		}
	}
	return addedPg, deletedPg, updatedPg
}

func UpdateNeighborConfig(logger log.Logger, curC, newC *BgpConfigSet) ([]Neighbor, []Neighbor, []Neighbor) {
	added := []Neighbor{}
	deleted := []Neighbor{}
	updated := []Neighbor{}

	for _, n := range newC.Neighbors {
		if idx := inSlice(n, curC.Neighbors); idx < 0 {
			added = append(added, n)
		} else if !n.Equal(&curC.Neighbors[idx]) {
			logger.Debug("Current neighbor config",
				log.Fields{
					"Topic": "Config",
					"Key":   curC.Neighbors[idx]})
			logger.Debug("New neighbor config",
				log.Fields{
					"Topic": "Config",
					"Key":   n})
			updated = append(updated, n)
		}
	}

	for _, n := range curC.Neighbors {
		if inSlice(n, newC.Neighbors) < 0 {
			deleted = append(deleted, n)
		}
	}
	return added, deleted, updated
}

func CheckPolicyDifference(logger log.Logger, currentPolicy *RoutingPolicy, newPolicy *RoutingPolicy) bool {
	logger.Debug("Current policy",
		log.Fields{
			"Topic": "Config",
			"Key":   currentPolicy})
	logger.Debug("New policy",
		log.Fields{
			"Topic": "Config",
			"Key":   newPolicy})

	var result bool
	if currentPolicy == nil && newPolicy == nil {
		result = false
	} else {
		if currentPolicy != nil && newPolicy != nil {
			result = !currentPolicy.Equal(newPolicy)
		} else {
			result = true
		}
	}
	return result
}
