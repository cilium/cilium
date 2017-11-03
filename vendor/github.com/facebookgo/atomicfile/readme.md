atomicfile [![Build Status](https://secure.travis-ci.org/facebookgo/atomicfile.png)](https://travis-ci.org/facebookgo/atomicfile)
==========

Documentation: https://godoc.org/github.com/facebookgo/atomicfile

NOTE: This package uses `os.Rename`, which may or may not be atomic on your
operating system. It is known to not be atomic on Windows.
https://github.com/natefinch/atomic provides a similar library that is atomic
on Windows as well and may be worth investigating.
