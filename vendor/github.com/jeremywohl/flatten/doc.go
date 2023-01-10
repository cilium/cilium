// Flatten makes flat, one-dimensional maps from arbitrarily nested ones.
//
// It turns map keys into compound
// names, in four default styles: dotted (`a.b.1.c`), path-like (`a/b/1/c`), Rails (`a[b][1][c]`),
// or with underscores (`a_b_1_c`).  Alternatively, you can pass a custom style.
//
// It takes input as either JSON strings or
// Go structures.  It knows how to traverse these JSON types: objects/maps, arrays and scalars.
//
// You can flatten JSON strings.
//
//	nested := `{
//	  "one": {
//	    "two": [
//	      "2a",
//	      "2b"
//	    ]
//	  },
//	  "side": "value"
//	}`
//
//	flat, err := flatten.FlattenString(nested, "", flatten.DotStyle)
//
//	// output: `{ "one.two.0": "2a", "one.two.1": "2b", "side": "value" }`
//
// Or Go maps directly.
//
//	nested := map[string]interface{}{
//		"a": "b",
//		"c": map[string]interface{}{
//			"d": "e",
//			"f": "g",
//		},
//		"z": 1.4567,
//	}
//
//	flat, err := flatten.Flatten(nested, "", flatten.RailsStyle)
//
//	// output:
//	// map[string]interface{}{
//	//	"a":    "b",
//	//	"c[d]": "e",
//	//	"c[f]": "g",
//	//	"z":    1.4567,
//	// }
//
// Let's try a custom style, with the first example above.
//
//	emdash := flatten.SeparatorStyle{Middle: "--"}
//	flat, err := flatten.FlattenString(nested, "", emdash)
//
//	// output: `{ "one--two--0": "2a", "one--two--1": "2b", "side": "value" }`
//
package flatten
