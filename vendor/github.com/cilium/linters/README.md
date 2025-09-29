Linters
=======

Linters is a collection of static analyzers for the Go programing language.
Although created for the needs of the Cilium project, they may be applied to any
Go codebase.

ioreadall
---------

`ioreadall` is an analyzer that checks for the use of
[(io|ioutil).ReadAll](https://pkg.go.dev/io#ReadAll). This function reads all
data from an `io.Reader` until `EOF`. However, if misused, it can be used as a
possible attack vector (e.g. an attacker gets the program to read a very large
file which fills up memory leader to a denial of service attack). Users are
encouraged to use alternative constructs such as making use of
[io.LimitReader](https://pkg.go.dev/io#LimitReader).

slowg
-----

`slowg` is an analyzer that checks for inappropriate use of `Logger.With` from
the `log/slog` (or `golang.org/x/exp/slog`) package.

`Logger.With()` (and `Logger.WithGroup()` creates a new Logger containing the
provided attributes. The parent logger is cloned when arguments are supplied,
which is a relatively expensive operation which should not be used in hot code
path.

For example, slowg would report the following call:

    log.With("key", val).Info("message")

Which should be replaced with the following one:

    log.Info("message", "key", val)

However, the slowg checker does not prevent the use of With and WithGroup.

	wlog := log.With("key", val)             // this is fine
	wlog.Info("info")                        // this is also fine
	wlog.With("more", "attr").Debug("debug") // this is flagged as inappropriate use
