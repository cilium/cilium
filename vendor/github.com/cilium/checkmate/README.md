Instructions
============

`checkmate` is meant to ease migrating off of `gopkg.in/check.v1`
and use the Go stdlib `testing` package instead. It achieves this by embedding
a `*testing.T` in `*check.C` and ripping out the test runner code. This means
that the following is now possible:

```go
func myUsefulHelper(tb testing.TB, ...) {
    // ...
}

func (s *Suite) TestSomething(c *C) {
    myUsefulHelper(c, ...)
}
```

Use it as a global replacement:

```sh
$ go mod edit -replace=gopkg.in/check.v1=github.com/cilium/checkmate
```

Or replace imports manually:

```go
import . "github.com/cilium/checkmate"
import check "github.com/cilium/checkmate"
```

## Caveats

This library differs from upstream `check` in the following ways:

* `Run*()` and `TestingT()` don't block until all tests have run
* `Run*()` don't return `Result` anymore, due to the above
* `C.Succeed*()` fails the test since there is no analog in `*testing.T`
* `RunConfig.KeepWorkDir` is not supported
* Any flags that are not benchmark related cause an error
* The output format of `check` is not preserved
