package types

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"sort"
)

type Labels map[string]string

type LabelsResponse struct {
	ID int `json:"id"`
}

func (lbls Labels) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	enc := json.NewEncoder(sha)
	sortedMap := lbls.sortMap()
	if err := enc.Encode(sortedMap); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (lbls Labels) sortMap() []string {
	var keys []string
	for k := range lbls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sortedMap []string
	for _, k := range keys {
		// We don't care if the values already have a '=' since this method is
		// only used to calculate a SHA256Sum
		str := fmt.Sprintf(`%s=%s`, k, lbls[k])
		sortedMap = append(sortedMap, str)
	}
	return sortedMap
}
