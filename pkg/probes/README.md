
## Requirements

Install bcc tools:

        sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
        echo "deb https://repo.iovisor.org/apt/xenial xenial main" | sudo tee /etc/apt/sources.list.d/iovisor.list
        sudo apt-get update
        sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)

Install gobpf

        go get -u github.com/iovisor/gobpf

## Hacks

List kprobes

        cat /sys/kernel/debug/tracing/kprobe_events


Clear all kprobes

        echo '' > /sys/kernel/debug/tracing/kprobe_events
