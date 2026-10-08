package diffmatchpatch

type index uint32

const runeSkipStart = 0xd800
const runeSkipEnd = 0xdfff + 1
const runeMax = 0x110000 // next invalid code point

func stringToIndex(text string) []index {
	runes := []rune(text)
	indexes := make([]index, len(runes))
	for i, r := range runes {
		if r < runeSkipEnd {
			indexes[i] = index(r)
		} else {
			indexes[i] = index(r) - (runeSkipEnd - runeSkipStart)
		}
	}
	return indexes
}

func indexesToString(indexes []index) string {
	runes := make([]rune, len(indexes))
	for i, index := range indexes {
		if index < runeSkipStart {
			runes[i] = rune(index)
		} else {
			runes[i] = rune(index + (runeSkipEnd - runeSkipStart))
		}
	}
	return string(runes)
}
