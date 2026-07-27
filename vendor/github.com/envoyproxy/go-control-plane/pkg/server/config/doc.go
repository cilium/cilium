/*
Config abstracts xDS server options into a unified configuration package
that allows for easy manipulation as well as unified passage of options
to individual xDS server implementations.

This enables code reduction as well as a unified source of config. Delta
and SOTW might have similar ordered responses through ADS and rather than
duplicating the logic across server implementations, we add the options
in this package which are passed down to each individual spec.

Each xDS implementation should implement their own functional opts.
It is recommended that config values be added in this package specifically,
but the individual opts functions should be in their respective
implementation package so the import looks like the following:

`sotw.WithOrderedADS()`
`delta.WithOrderedADS()`

this allows for easy inference as to which opt applies to what implementation.
*/

package config
