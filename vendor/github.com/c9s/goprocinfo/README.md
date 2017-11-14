goprocinfo
===================

/proc information parser for Go.

Usage
---------------

```go
import (
	"log"

	linuxproc "github.com/c9s/goprocinfo/linux"
)

stat, err := linuxproc.ReadStat("/proc/stat")
if err != nil {
	log.Fatal("stat read fail")
}

for _, s := range stat.CPUStats {
	// s.User
	// s.Nice
	// s.System
	// s.Idle
	// s.IOWait
}

// stat.CPUStatAll
// stat.CPUStats
// stat.Processes
// stat.BootTime
// ... etc
```

Documentation
---------------

Full documentation is available at [Godoc](https://godoc.org/github.com/c9s/goprocinfo/linux).


Reference
------------

* http://www.mjmwired.net/kernel/Documentation/filesystems/proc.txt

License
-------

goprocinfo is distributed under the MIT license.
