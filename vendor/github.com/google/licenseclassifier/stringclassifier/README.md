# StringClassifier

StringClassifier is a library to classify an unknown text against a set of known
texts. The classifier uses the [Levenshtein Distance] algorithm to determine
which of the known texts most closely matches the unknown text. The Levenshtein
Distance is normalized into a "confidence percentage" between 1 and 0, where 1.0
indicates an exact match and 0.0 indicates a complete mismatch.

[Levenshtein Distance]: https://en.wikipedia.org/wiki/Levenshtein_distance

## Types of matching

There are two kinds of matching algorithms the string classifier can perform:

1. [Nearest matching](#nearest), and
2. [Multiple matching](#multiple).

### Normalization

To get the best match, normalizing functions can be applied to the texts. For
example, flattening whitespaces removes a lot of inconsequential formatting
differences that would otherwise lower the matching confidence percentage.

```go
sc := stringclassifier.New(stringclassifier.FlattenWhitespace, strings.ToLower)
```

The normalizating functions are run on all the known texts that are added to the
classifier. They're also run on the unknown text before classification.

### Nearest matching {#nearest}

A nearest match returns the name of the known text that most closely matches the
full unknown text. This is most useful when the unknown text doesn't have
extraneous text around it.

Example:

```go
func IdentifyText(sc *stringclassifier.Classifier, name, unknown string) {
  m := sc.NearestMatch(unknown)
  log.Printf("The nearest match to %q is %q (confidence: %v)", name, m.Name, m.Confidence)
}
```

## Multiple matching {#multiple}

Multiple matching identifies all of the known texts which may exist in the
unknown text. It can also detect a known text in an unknown text even if there's
extraneous text around the unknown text. As with nearest matching, a confidence
percentage for each match is given.

Example:

```go
log.Printf("The text %q contains:", name)
for _, m := range sc.MultipleMatch(unknown, false) {
  log.Printf("  %q (conf: %v, offset: %v)", m.Name, m.Confidence, m.Offset)
}
```

## Disclaimer

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.
