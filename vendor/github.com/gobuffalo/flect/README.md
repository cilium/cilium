# Flect

[![Go Reference](https://pkg.go.dev/badge/github.com/gobuffalo/flect.svg)](https://pkg.go.dev/github.com/gobuffalo/flect)
[![Standard Test](https://github.com/gobuffalo/flect/actions/workflows/standard-go-test.yml/badge.svg)](https://github.com/gobuffalo/flect/actions/workflows/standard-go-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gobuffalo/flect)](https://goreportcard.com/report/github.com/gobuffalo/flect)

This is a new inflection engine to replace [https://github.com/markbates/inflect](https://github.com/markbates/inflect) designed to be more modular, more readable, and easier to fix issues on than the original.

Flect provides word inflection features such as `Singularize` and `Pluralize`
for English nouns and text utility features such as `Camelize`, `Capitalize`,
`Humanize`, and more.

Due to the flexibly-complex nature of English noun inflection, it is almost
impossible to cover all exceptions (such as identical/irregular plural).
With this reason along with the main purpose of Flect, which is to make it
easy to develop web application in Go, Flect has limitations with its own
rules.

* It covers regular rule (adding -s or -es and of the word)
* It covers well-known irregular rules (such as -is to -es, -f to -ves, etc)
  * https://en.wiktionary.org/wiki/Appendix:English_irregular_nouns#Rules
* It covers well-known irregular words (such as children, men, etc)
* If a word can be countable and uncountable like milk or time, it will be
  treated as countable.
* If a word has more than one plural forms, which means it has at least one
  irregular plural, we tried to find most popular one. (The selected plural
  could be odd to you, please feel free to open an issue with back data)
  * For example, we selected "stadiums" over "stadia", "dwarfs" over "dwarves"
  * One or combination of en.wiktionary.org, britannica.com, and
    trends.google.com are used to check the recent usage trends.
* However, we cannot cover all cases and some of our cases could not fit with
  your situation. You can override the default with functions such as
  `InsertPlural()`, `InsertSingular()`, or `LoadInfrections()`.
* If you have a json file named `inflections.json` in your application root,
  the file will be automatically loaded as your custom inflection dictionary.

## Installation

```console
$ go get github.com/gobuffalo/flect
```


## Packages

### `github.com/gobuffalo/flect`

The `github.com/gobuffalo/flect` package contains "basic" inflection tools, like pluralization, singularization, etc...

#### The `Ident` Type

In addition to helpful methods that take in a `string` and return a `string`, there is an `Ident` type that can be used to create new, custom, inflection rules.

The `Ident` type contains two fields.

* `Original` - This is the original `string` that was used to create the `Ident`
* `Parts` - This is a `[]string` that represents all of the "parts" of the string, that have been split apart, making the segments easier to work with

Examples of creating new inflection rules using `Ident` can be found in the `github.com/gobuffalo/flect/name` package.

### `github.com/gobuffalo/flect/name`

The `github.com/gobuffalo/flect/name` package contains more "business" inflection rules like creating proper names, table names, etc...
