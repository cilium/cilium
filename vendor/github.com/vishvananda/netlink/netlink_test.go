package netlink

import (
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netns"
)

type tearDownNetlinkTest func()

func skipUnlessRoot(t *testing.T) {
	if os.Getuid() != 0 {
		msg := "Skipped test because it requires root privileges."
		log.Printf(msg)
		t.Skip(msg)
	}
}

func setUpNetlinkTest(t *testing.T) tearDownNetlinkTest {
	skipUnlessRoot(t)

	// new temporary namespace so we don't pollute the host
	// lock thread since the namespace is thread local
	runtime.LockOSThread()
	var err error
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

func setUpMPLSNetlinkTest(t *testing.T) tearDownNetlinkTest {
	if _, err := os.Stat("/proc/sys/net/mpls/platform_labels"); err != nil {
		msg := "Skipped test because it requires MPLS support."
		log.Printf(msg)
		t.Skip(msg)
	}
	f := setUpNetlinkTest(t)
	setUpF := func(path, value string) {
		file, err := os.Create(path)
		defer file.Close()
		if err != nil {
			t.Fatalf("Failed to open %s: %s", path, err)
		}
		file.WriteString(value)
	}
	setUpF("/proc/sys/net/mpls/platform_labels", "1024")
	setUpF("/proc/sys/net/mpls/conf/lo/input", "1")
	return f
}
