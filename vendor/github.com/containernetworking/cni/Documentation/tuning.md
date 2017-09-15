# tuning plugin

## Overview

This plugin can change some system controls (sysctls) in the network namespace.
It does not create any network interfaces and therefore does not bring connectivity by itself.
It is only useful when used in addition to other plugins.

## Operation
The following network configuration file
```
{
  "name": "mytuning",
  "type": "tuning",
  "sysctl": {
          "net.core.somaxconn": "500"
  }
}
```
will set /proc/sys/net/core/somaxconn to 500.
Other sysctls can be modified as long as they belong to the network namespace (`/proc/sys/net/*`).

A successful result would simply be:
```
{ }
```

## Network sysctls documentation

Some network sysctls are documented in the Linux sources:

- [Documentation/sysctl/net.txt](https://www.kernel.org/doc/Documentation/sysctl/net.txt)
- [Documentation/networking/ip-sysctl.txt](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [Documentation/networking/](https://www.kernel.org/doc/Documentation/networking/)
