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

timeafter
---------

`timeafter` is an analyzer that checks for the use of
[time.After](https://pkg.go.dev/time#After) instances in loops. As stated in its
documentation, the underlying Timer is not recovered by the garbage collector
until the timer fires.
