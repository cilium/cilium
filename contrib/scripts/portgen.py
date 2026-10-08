#!/usr/bin/env python3
# This script samples TCP/UDP source port generator in the kernel by opening as
# many connections as it can and storing the source ports used. The clients and
# the server run in separate network namespaces to remove interference with the
# connections already opened on the host.
#
# Suggested usage to form a C array suitable for the BPF unit tests:
# contrib/scripts/portgen.py | awk 'NR%10 {printf("%s, ", $0); next} {printf("%s,\n", $0)}' | sed -e 's/^/\t/' -e '$s/ $//' > bpf/tests/tcp_ports0.txt
# contrib/scripts/portgen.py -u | awk 'NR%10 {printf("%s, ", $0); next} {printf("%s,\n", $0)}' | sed -e 's/^/\t/' -e '$s/ $//' > bpf/tests/udp_ports0.txt

from contextlib import contextmanager
import argparse
import errno
import os
import resource
import subprocess
import socket


class NetNamespace:
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        subprocess.check_call(['ip', 'netns', 'add', self.name])
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        subprocess.check_call(['ip', 'netns', 'del', self.name])

    def check_call(self, args, **kwargs):
        subprocess.check_call(['ip', 'netns', 'exec', self.name, *args], **kwargs)

    @contextmanager
    def enter(self):
        with open(f'/proc/{os.getpid()}/ns/net', 'r') as old:
            with open(f'/run/netns/{self.name}', 'r') as new:
                os.setns(new.fileno(), os.CLONE_NEWNET)
            try:
                yield
            finally:
                os.setns(old.fileno(), os.CLONE_NEWNET)


class VethPair:
    def __init__(self, name1, name2):
        self.name1 = name1
        self.name2 = name2

    def __enter__(self):
        subprocess.check_call(['ip', 'link', 'add', self.name1, 'type', 'veth', 'peer', 'name', self.name2])
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        subprocess.check_call(['ip', 'link', 'del', self.name1])


def port_generator(server_addr, server_port, udp):
    clients = []
    while True:
        socket_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        client = socket.socket(socket.AF_INET, socket_type)
        try:
            if udp:
                client.sendto(bytes('hello', 'ascii'), (server_addr, server_port))
            else:
                client.connect((server_addr, server_port))
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL:
                break
            raise
        clients.append(client)
        yield client.getsockname()[1]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--udp', action='store_true',
                        help='open UDP connections instead of TCP')
    args = parser.parse_args()

    nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile_hard, nofile_hard))

    with NetNamespace('portgen1') as ns1, NetNamespace('portgen2') as ns2:
        ns1.check_call(['ip', 'link', 'set', 'lo', 'up'])
        ns2.check_call(['ip', 'link', 'set', 'lo', 'up'])
        with VethPair('pgen0', 'pgen1') as veth:
            subprocess.check_call(['ip', 'link', 'set', veth.name1, 'netns', ns1.name])
            try:
                subprocess.check_call(['ip', 'link', 'set', veth.name2, 'netns', ns2.name])
                ns1.check_call(['ip', 'addr', 'replace', '10.38.73.1/24', 'dev', veth.name1])
                ns1.check_call(['ip', 'link', 'set', veth.name1, 'up'])
                ns2.check_call(['ip', 'addr', 'replace', '10.38.73.2/24', 'dev', veth.name2])
                ns2.check_call(['ip', 'link', 'set', veth.name2, 'up'])
                with ns2.enter():
                    socket_type = socket.SOCK_DGRAM if args.udp else socket.SOCK_STREAM
                    server = socket.socket(socket.AF_INET, socket_type)
                    server.bind(('', 8080))
                    if not args.udp:
                        server.listen()
                with ns1.enter():
                    clients = []
                    try:
                        for port in port_generator('10.38.73.2', 8080, args.udp):
                            if args.udp:
                                server.recvfrom(8)
                            else:
                                clients.append(server.accept()[0])
                            print(port)
                    finally:
                        for c in clients:
                            c.close()
                        clients = []
            finally:
                ns1.check_call(['ip', 'link', 'set', veth.name1, 'netns', str(os.getpid())])
