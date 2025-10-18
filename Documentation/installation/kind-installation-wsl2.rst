=======================================================
Installing KinD and Cilium on WSL2 with a Custom Kernel
=======================================================

This guide describes how to prepare Windows Subsystem for Linux 2 (WSL2) for KinD and Cilium using a custom kernel with the required modules.

-----------------
1. Prerequisites
-----------------
- Windows 10/11 with WSL2 enabled
- Docker Desktop installed
- Sufficient permissions to run containers

-----------------
2. Installing WSL2
-----------------
WSL2 allows you to run a complete Linux kernel inside Windows using lightweight virtualization.

To install WSL2, open PowerShell and run::

    wsl --install

Set your preferred Linux distribution (e.g., Ubuntu) to use WSL2::

    wsl --set-version Ubuntu 2

------------------------------
3. Building a Custom WSL2 Kernel
------------------------------

Start a Docker container for building the kernel::

    docker run --name wsl-kernel-builder --rm -it ubuntu@sha256:9d6a8699fb5c9c39cf08a0871bd6219f0400981c570894cd8cbea30d3424a31f bash

Inside the container, set up your environment::

    export WSL_COMMIT_REF=linux-msft-wsl-5.10.60.1
    apt update && apt install -y git build-essential flex bison libssl-dev libelf-dev bc dwarves
    mkdir src
    cd src
    git init
    git remote add origin https://github.com/microsoft/WSL2-Linux-Kernel.git
    git config --local gc.auto 0
    git -c protocol.version=2 fetch --no-tags --prune --progress --no-recurse-submodules --depth=1 origin +${WSL_COMMIT_REF}:refs/remotes/origin/build/linux-msft-wsl-5.10.y
    git checkout --progress --force -B build/linux-msft-wsl-5.10.y refs/remotes/origin/build/linux-msft-wsl-5.10.y

Enable required kernel modules in *Microsoft/config-wsl*::

    # Session affinity for clientIP
    sed -i 's/# CONFIG_NETFILTER_XT_MATCH_RECENT is not set/CONFIG_NETFILTER_XT_MATCH_RECENT=y/' Microsoft/config-wsl

    # Required for Cilium
    sed -i 's/# CONFIG_NETFILTER_XT_TARGET_CT is not set/CONFIG_NETFILTER_XT_TARGET_CT=y/' Microsoft/config-wsl
    sed -i 's/# CONFIG_NETFILTER_XT_TARGET_TPROXY is not set/CONFIG_NETFILTER_XT_TARGET_TPROXY=y/' Microsoft/config-wsl
    sed -i 's/# CONFIG_IPV6_MULTIPLE_TABLES is not set/CONFIG_IPV6_MULTIPLE_TABLES=y/' Microsoft/config-wsl

Build the kernel::

    make -j2 KCONFIG_CONFIG=Microsoft/config-wsl

*Optionally*, if your build environment has enough cores and memory, you may use::

    make -j7 KCONFIG_CONFIG=Microsoft/config-wsl

------------------------------------------
4. Copy the Custom Kernel Out of the Container
------------------------------------------
Open a new PowerShell terminal and run::

    docker cp wsl-kernel-builder:/src/arch/x86/boot/bzImage .

This copies `bzImage` to your `%UserProfile%` directory on Windows.

-----------------------------------
5. Configure WSL2 to Use Your Custom Kernel
-----------------------------------
Edit the file at `C:\Users\<your_user>\.wslconfig` and add::

    [wsl2]
    kernel=C:\\Users\\<your_user>\\bzImage

**Note:** Keep the double backslashes in the path.

---------------------------
6. Restart WSL2 and Docker Desktop
---------------------------
Shut down WSL2::

    wsl --shutdown

Then restart Docker Desktop.

-------------------------------
7. Install KinD and Cilium
-------------------------------
Start KinD and follow the Cilium installation instructions to complete your setup. For detailed steps, visit the Cilium Documentation at: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/
