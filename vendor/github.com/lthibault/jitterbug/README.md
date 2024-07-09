# jitterbug

Tickers with random jitter

[![Godoc Reference](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/lthibault/jitterbug)
[![Go Report Card](https://goreportcard.com/badge/github.com/SentimensRG/ctx?style=flat-square)](https://goreportcard.com/report/github.com/lthibault/jitterbug)

## Installation

```bash
go get -u github.com/lthibault/jitterbug
```

## Usage

Jitterbug is used by instantiating a `jitterbug.Ticker` with an interval and a
`jitterbug.Jitter`.  The former specifies a baseline interval for the ticker,
to which a jitter is added by the latter.

```go
package main

import (
    "log"

    "github.com/lthibault/jitterbug"
)

func main() {
    t := jitterbug.New(
        time.Millisecond * 300,
        &jitterbug.Norm{ Stdev: time.Millisecond * 100 },
    )

    // jitterbug.Ticker behaves like time.Ticker
    for tick := <- range t.C {
        log.Println(tick)
    }
}

```

Jitterbug is compatible with the univariate distributions from [GoNum](https://godoc.org/gonum.org/v1/gonum/stat/distuv).  For example:

```go
t := jitterbug.New(
    time.Millisecond * 300,
    &jitterbug.Univariate{
        Sampler: &distruv.Gamma{
            // Tip: cast time.Duration as float64 when using gonum's distruv
            Alpha: float64(time.Millisecond * 100),
            Beta:  float64(time.Millisecond * 200),
        }
    },
)
```

## Compatible libraries

- [GoNum](https://github.com/gonum/gonum), specifically the [univariate distributions](https://godoc.org/gonum.org/v1/gonum/stat/distuv).
- [Suture](https://github.com/thejerf/suture) can use jitterbug for it's backoff [durations](https://godoc.org/github.com/thejerf/suture#Jitter).

## RFC

If you find this useful please let me know:  <l.thibault@sentimens.com>

Seriously, even if you just used it in your weekend project, I'd like to hear
about it :)
