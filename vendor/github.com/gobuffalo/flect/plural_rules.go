package flect

import "fmt"

var pluralRules = []rule{}

// AddPlural adds a rule that will replace the given suffix with the replacement suffix.
// The name is confusing. This function will be deprecated in the next release.
func AddPlural(suffix string, repl string) {
	InsertPluralRule(suffix, repl)
}

// InsertPluralRule inserts a rule that will replace the given suffix with
// the repl(acement) at the begining of the list of the pluralize rules.
func InsertPluralRule(suffix, repl string) {
	pluralMoot.Lock()
	defer pluralMoot.Unlock()

	pluralRules = append([]rule{{
		suffix: suffix,
		fn:     simpleRuleFunc(suffix, repl),
	}}, pluralRules...)

	pluralRules = append([]rule{{
		suffix: repl,
		fn:     noop,
	}}, pluralRules...)
}

type word struct {
	singular       string
	plural         string
	alternative    string
	unidirectional bool // plural to singular is not possible (or bad)
	uncountable    bool
	exact          bool
}

// dictionary is the main table for singularize and pluralize.
// All words in the dictionary will be added to singleToPlural, pluralToSingle
// and singlePluralAssertions by init() functions.
var dictionary = []word{
	// identicals https://en.wikipedia.org/wiki/English_plurals#Nouns_with_identical_singular_and_plural
	{singular: "aircraft", plural: "aircraft"},
	{singular: "beef", plural: "beef", alternative: "beefs"},
	{singular: "bison", plural: "bison"},
	{singular: "blues", plural: "blues", unidirectional: true},
	{singular: "chassis", plural: "chassis"},
	{singular: "deer", plural: "deer"},
	{singular: "fish", plural: "fish", alternative: "fishes"},
	{singular: "moose", plural: "moose"},
	{singular: "police", plural: "police"},
	{singular: "salmon", plural: "salmon", alternative: "salmons"},
	{singular: "series", plural: "series"},
	{singular: "sheep", plural: "sheep"},
	{singular: "shrimp", plural: "shrimp", alternative: "shrimps"},
	{singular: "species", plural: "species"},
	{singular: "swine", plural: "swine", alternative: "swines"},
	{singular: "trout", plural: "trout", alternative: "trouts"},
	{singular: "tuna", plural: "tuna", alternative: "tunas"},
	{singular: "you", plural: "you"},
	// -en https://en.wikipedia.org/wiki/English_plurals#Plurals_in_-(e)n
	{singular: "child", plural: "children"},
	{singular: "ox", plural: "oxen", exact: true},
	// apophonic https://en.wikipedia.org/wiki/English_plurals#Apophonic_plurals
	{singular: "foot", plural: "feet"},
	{singular: "goose", plural: "geese"},
	{singular: "man", plural: "men"},
	{singular: "human", plural: "humans"}, // not humen
	{singular: "louse", plural: "lice", exact: true},
	{singular: "mouse", plural: "mice"},
	{singular: "tooth", plural: "teeth"},
	{singular: "woman", plural: "women"},
	// misc https://en.wikipedia.org/wiki/English_plurals#Miscellaneous_irregular_plurals
	{singular: "die", plural: "dice", exact: true},
	{singular: "person", plural: "people"},

	// Words from French that end in -u add an x; in addition to eau to eaux rule
	{singular: "adieu", plural: "adieux", alternative: "adieus"},
	{singular: "fabliau", plural: "fabliaux"},
	{singular: "bureau", plural: "bureaus", alternative: "bureaux"}, // popular

	// Words from Greek that end in -on change -on to -a; in addition to hedron rule
	{singular: "criterion", plural: "criteria"},
	{singular: "ganglion", plural: "ganglia", alternative: "ganglions"},
	{singular: "lexicon", plural: "lexica", alternative: "lexicons"},
	{singular: "mitochondrion", plural: "mitochondria", alternative: "mitochondrions"},
	{singular: "noumenon", plural: "noumena"},
	{singular: "phenomenon", plural: "phenomena"},
	{singular: "taxon", plural: "taxa"},

	// Words from Latin that end in -um change -um to -a; in addition to some rules
	{singular: "media", plural: "media"}, // popular case: media -> media
	{singular: "medium", plural: "media", alternative: "mediums", unidirectional: true},
	{singular: "stadium", plural: "stadiums", alternative: "stadia"},
	{singular: "aquarium", plural: "aquaria", alternative: "aquariums"},
	{singular: "auditorium", plural: "auditoria", alternative: "auditoriums"},
	{singular: "symposium", plural: "symposia", alternative: "symposiums"},
	{singular: "curriculum", plural: "curriculums", alternative: "curricula"}, // ulum
	{singular: "quota", plural: "quotas"},

	// Words from Latin that end in -us change -us to -i or -era
	{singular: "alumnus", plural: "alumni", alternative: "alumnuses"}, // -i
	{singular: "bacillus", plural: "bacilli"},
	{singular: "cactus", plural: "cacti", alternative: "cactuses"},
	{singular: "coccus", plural: "cocci"},
	{singular: "focus", plural: "foci", alternative: "focuses"},
	{singular: "locus", plural: "loci", alternative: "locuses"},
	{singular: "nucleus", plural: "nuclei", alternative: "nucleuses"},
	{singular: "octopus", plural: "octupuses", alternative: "octopi"},
	{singular: "radius", plural: "radii", alternative: "radiuses"},
	{singular: "syllabus", plural: "syllabi"},
	{singular: "corpus", plural: "corpora", alternative: "corpuses"}, // -ra
	{singular: "genus", plural: "genera"},

	// Words from Latin that end in -a change -a to -ae
	{singular: "alumna", plural: "alumnae"},
	{singular: "vertebra", plural: "vertebrae"},
	{singular: "differentia", plural: "differentiae"}, // -tia
	{singular: "minutia", plural: "minutiae"},
	{singular: "vita", plural: "vitae"},   // -ita
	{singular: "larva", plural: "larvae"}, // -va
	{singular: "postcava", plural: "postcavae"},
	{singular: "praecava", plural: "praecavae"},
	{singular: "uva", plural: "uvae"},

	// Words from Latin that end in -ex change -ex to -ices
	{singular: "apex", plural: "apices", alternative: "apexes"},
	{singular: "codex", plural: "codices", alternative: "codexes"},
	{singular: "index", plural: "indices", alternative: "indexes"},
	{singular: "latex", plural: "latices", alternative: "latexes"},
	{singular: "vertex", plural: "vertices", alternative: "vertexes"},
	{singular: "vortex", plural: "vortices", alternative: "vortexes"},

	// Words from Latin that end in -ix change -ix to -ices (eg, matrix becomes matrices)
	{singular: "appendix", plural: "appendices", alternative: "appendixes"},
	{singular: "radix", plural: "radices", alternative: "radixes"},
	{singular: "helix", plural: "helices", alternative: "helixes"},

	// Words from Latin that end in -is change -is to -es
	{singular: "axis", plural: "axes", exact: true},
	{singular: "crisis", plural: "crises"},
	{singular: "ellipsis", plural: "ellipses", unidirectional: true}, // ellipse
	{singular: "genesis", plural: "geneses"},
	{singular: "oasis", plural: "oases"},
	{singular: "thesis", plural: "theses"},
	{singular: "testis", plural: "testes"},
	{singular: "base", plural: "bases"}, // popular case
	{singular: "basis", plural: "bases", unidirectional: true},

	{singular: "alias", plural: "aliases", exact: true}, // no alia, no aliasis
	{singular: "vedalia", plural: "vedalias"},           // no vedalium, no vedaliases

	// Words that end in -ch, -o, -s, -sh, -x, -z (can be conflict with the others)
	{singular: "use", plural: "uses", exact: true}, // us vs use
	{singular: "abuse", plural: "abuses"},
	{singular: "cause", plural: "causes"},
	{singular: "clause", plural: "clauses"},
	{singular: "cruse", plural: "cruses"},
	{singular: "excuse", plural: "excuses"},
	{singular: "fuse", plural: "fuses"},
	{singular: "house", plural: "houses"},
	{singular: "misuse", plural: "misuses"},
	{singular: "muse", plural: "muses"},
	{singular: "pause", plural: "pauses"},
	{singular: "ache", plural: "aches"},
	{singular: "topaz", plural: "topazes"},
	{singular: "buffalo", plural: "buffaloes", alternative: "buffalos"},
	{singular: "potato", plural: "potatoes"},
	{singular: "tomato", plural: "tomatoes"},

	// uncountables
	{singular: "equipment", uncountable: true},
	{singular: "information", uncountable: true},
	{singular: "jeans", uncountable: true},
	{singular: "money", uncountable: true},
	{singular: "news", uncountable: true},
	{singular: "rice", uncountable: true},

	// exceptions: -f to -ves, not -fe
	{singular: "dwarf", plural: "dwarfs", alternative: "dwarves"},
	{singular: "hoof", plural: "hoofs", alternative: "hooves"},
	{singular: "thief", plural: "thieves"},
	// exceptions: instead of -f(e) to -ves
	{singular: "chive", plural: "chives"},
	{singular: "hive", plural: "hives"},
	{singular: "move", plural: "moves"},

	// exceptions: instead of -y to -ies
	{singular: "movie", plural: "movies"},
	{singular: "cookie", plural: "cookies"},

	// exceptions: instead of -um to -a
	{singular: "pretorium", plural: "pretoriums"},
	{singular: "agenda", plural: "agendas"}, // instead of plural of agendum
	// exceptions: instead of -um to -a (chemical element names)

	// Words from Latin that end in -a change -a to -ae
	{singular: "formula", plural: "formulas", alternative: "formulae"}, // also -um/-a

	// exceptions: instead of -o to -oes
	{singular: "shoe", plural: "shoes"},
	{singular: "toe", plural: "toes", exact: true},
	{singular: "graffiti", plural: "graffiti"},

	// abbreviations
	{singular: "ID", plural: "IDs", exact: true},
}

// singleToPlural is the highest priority map for Pluralize().
// singularToPluralSuffixList is used to build pluralRules for suffixes and
// compound words.
var singleToPlural = map[string]string{}

// pluralToSingle is the highest priority map for Singularize().
// singularToPluralSuffixList is used to build singularRules for suffixes and
// compound words.
var pluralToSingle = map[string]string{}

// NOTE: This map should not be built as reverse map of singleToPlural since
// there are words that has the same plurals.

// build singleToPlural and pluralToSingle with dictionary
func init() {
	for _, wd := range dictionary {
		if singleToPlural[wd.singular] != "" {
			panic(fmt.Errorf("map singleToPlural already has an entry for %s", wd.singular))
		}

		if wd.uncountable && wd.plural == "" {
			wd.plural = wd.singular
		}

		if wd.plural == "" {
			panic(fmt.Errorf("plural for %s is not provided", wd.singular))
		}

		singleToPlural[wd.singular] = wd.plural

		if !wd.unidirectional {
			if pluralToSingle[wd.plural] != "" {
				panic(fmt.Errorf("map pluralToSingle already has an entry for %s", wd.plural))
			}
			pluralToSingle[wd.plural] = wd.singular

			if wd.alternative != "" {
				if pluralToSingle[wd.alternative] != "" {
					panic(fmt.Errorf("map pluralToSingle already has an entry for %s", wd.alternative))
				}
				pluralToSingle[wd.alternative] = wd.singular
			}
		}
	}
}

type singularToPluralSuffix struct {
	singular string
	plural   string
}

// singularToPluralSuffixList is a list of "bidirectional" suffix rules for
// the irregular plurals follow such rules.
//
// NOTE: IMPORTANT! The order of items in this list is the rule priority, not
// alphabet order. The first match will be used to inflect.
var singularToPluralSuffixList = []singularToPluralSuffix{
	// https://en.wiktionary.org/wiki/Appendix:English_irregular_nouns#Rules
	// Words that end in -f or -fe change -f or -fe to -ves
	{"tive", "tives"}, // exception
	{"eaf", "eaves"},
	{"oaf", "oaves"},
	{"afe", "aves"},
	{"arf", "arves"},
	{"rfe", "rves"},
	{"rf", "rves"},
	{"lf", "lves"},
	{"fe", "ves"}, // previously '[a-eg-km-z]fe' TODO: regex support

	// Words that end in -y preceded by a consonant change -y to -ies
	{"ay", "ays"},
	{"ey", "eys"},
	{"oy", "oys"},
	{"quy", "quies"},
	{"uy", "uys"},
	{"y", "ies"}, // '[^aeiou]y'

	// Words from French that end in -u add an x (eg, château becomes châteaux)
	{"eau", "eaux"}, // it seems like 'eau' is the most popular form of this rule

	// Words from Latin that end in -a change -a to -ae; before -on to -a and -um to -a
	{"bula", "bulae"},
	{"dula", "bulae"},
	{"lula", "bulae"},
	{"nula", "bulae"},
	{"vula", "bulae"},

	// Words from Greek that end in -on change -on to -a (eg, polyhedron becomes polyhedra)
	// https://en.wiktionary.org/wiki/Category:English_irregular_plurals_ending_in_"-a"
	{"hedron", "hedra"},

	// Words from Latin that end in -um change -um to -a (eg, minimum becomes minima)
	// https://en.wiktionary.org/wiki/Category:English_irregular_plurals_ending_in_"-a"
	{"ium", "ia"}, // some exceptions especially chemical element names
	{"seum", "seums"},
	{"eum", "ea"},
	{"oum", "oa"},
	{"stracum", "straca"},
	{"dum", "da"},
	{"elum", "ela"},
	{"ilum", "ila"},
	{"olum", "ola"},
	{"ulum", "ula"},
	{"llum", "lla"},
	{"ylum", "yla"},
	{"imum", "ima"},
	{"ernum", "erna"},
	{"gnum", "gna"},
	{"brum", "bra"},
	{"crum", "cra"},
	{"terum", "tera"},
	{"serum", "sera"},
	{"trum", "tra"},
	{"antum", "anta"},
	{"atum", "ata"},
	{"entum", "enta"},
	{"etum", "eta"},
	{"itum", "ita"},
	{"otum", "ota"},
	{"utum", "uta"},
	{"ctum", "cta"},
	{"ovum", "ova"},

	// Words from Latin that end in -us change -us to -i or -era
	// not easy to make a simple rule. just add them all to the dictionary

	// Words from Latin that end in -ex change -ex to -ices (eg, vortex becomes vortices)
	// Words from Latin that end in -ix change -ix to -ices (eg, matrix becomes matrices)
	//    for example, -dix, -dex, and -dice will have the same plural form so
	//    making a simple rule is not possible for them
	{"trix", "trices"}, // ignore a few words end in trice

	// Words from Latin that end in -is change -is to -es (eg, thesis becomes theses)
	// -sis and -se has the same plural -ses so making a rule is not easy too.
	{"iasis", "iases"},
	{"mesis", "meses"},
	{"kinesis", "kineses"},
	{"resis", "reses"},
	{"gnosis", "gnoses"}, // e.g. diagnosis
	{"opsis", "opses"},   // e.g. synopsis
	{"ysis", "yses"},     // e.g. analysis

	// Words that end in -ch, -o, -s, -sh, -x, -z
	{"ouse", "ouses"},
	{"lause", "lauses"},
	{"us", "uses"}, // use/uses is in the dictionary

	{"ch", "ches"},
	{"io", "ios"},
	{"sh", "shes"},
	{"ss", "sses"},
	{"ez", "ezzes"},
	{"iz", "izzes"},
	{"tz", "tzes"},
	{"zz", "zzes"},
	{"ano", "anos"},
	{"lo", "los"},
	{"to", "tos"},
	{"oo", "oos"},
	{"o", "oes"},
	{"x", "xes"},

	// for abbreviations
	{"S", "Ses"},

	// excluded rules: seems rare
	// Words from Hebrew that add -im or -ot (eg, cherub becomes cherubim)
	// - cherub (cherubs or cherubim), seraph (seraphs or seraphim)
	// Words from Greek that end in -ma change -ma to -mata
	// - The most of words end in -ma are in this category but it looks like
	//   just adding -s is more popular.
	// Words from Latin that end in -nx change -nx to -nges
	// - The most of words end in -nx are in this category but it looks like
	//   just adding -es is more popular. (sphinxes)

	// excluded rules: don't care at least for now:
	// Words that end in -ful that add an s after the -ful
	// Words that end in -s or -ese denoting a national of a particular country
	// Symbols or letters, which often add -'s
}

func init() {
	for i := len(singularToPluralSuffixList) - 1; i >= 0; i-- {
		InsertPluralRule(singularToPluralSuffixList[i].singular, singularToPluralSuffixList[i].plural)
		InsertSingularRule(singularToPluralSuffixList[i].plural, singularToPluralSuffixList[i].singular)
	}

	// build pluralRule and singularRule with dictionary for compound words
	for _, wd := range dictionary {
		if wd.exact {
			continue
		}

		if wd.uncountable && wd.plural == "" {
			wd.plural = wd.singular
		}

		InsertPluralRule(wd.singular, wd.plural)

		if !wd.unidirectional {
			InsertSingularRule(wd.plural, wd.singular)

			if wd.alternative != "" {
				InsertSingularRule(wd.alternative, wd.singular)
			}
		}
	}
}
