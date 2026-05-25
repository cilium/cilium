package cache

// Key is an internal sorting data structure we can use to
// order responses by Type and their associated watch IDs.
type key struct {
	ID      int64
	TypeURL string
}

// Keys implements Go's sorting.Sort interface
type keys []key

func (k keys) Len() int {
	return len(k)
}

// Less compares the typeURL and determines what order things should be sent.
func (k keys) Less(i, j int) bool {
	return GetResponseType(k[i].TypeURL) < GetResponseType(k[j].TypeURL)
}

func (k keys) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
