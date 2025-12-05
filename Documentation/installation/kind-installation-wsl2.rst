**************************************
Installing KinD and Cilium on WSL2 
**************************************

This guide describes how to prepare Windows Subsystem for Linux 2 (WSL2) for KinD and Cilium using a custom kernel with the required modules.

-----------------
1. Prerequisites
-----------------
- Windows 10/11 with WSL2 enabled
- Docker Desktop installed
- Sufficient permissions to run containers

-------------------
2. Installing WSL2
-------------------
WSL2 allows you to run a complete Linux kernel inside Windows using lightweight virtualization.

To install WSL2, open PowerShell and run::

    wsl --install

Set your preferred Linux distribution (e.g., Ubuntu) to use WSL2::

    wsl --set-version Ubuntu 2

Ensure your WSL2 kernel is at least 6.x::

    wsl --version
    # Kernel version: 6.x or higher 

    If not, run::
        
        wsl --update
-------------------------------
3. Install KinD and Cilium
-------------------------------
Start KinD and follow the Cilium installation instructions to complete your setup. For detailed steps, 
visit the Cilium Documentation at: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/ and 
KinD Documentation at https://kind.sigs.k8s.io/#installation-and-usage

----------------------------------------
4. Known Restrictions for Cilium on WSL2
----------------------------------------

While Cilium now works out-of-the-box in WSL2 with kernel version 6.6.x or higher, there are still important limitations to be aware of:

- **Limited Kernel Feature Set on Older WSL2 Kernels:**
  Cilium requires specific kernel modules and features (eBPF, Netfilter, etc.). With modern WSL2 kernels (6.x+), most are built-in or loadable. However, on older kernels (≤5.15), you may lack required features and need a custom kernel build.

- **Advanced Features May Be Unsupported:**
  IPsec transparent encryption, advanced eBPF tracing, and certain observability integrations may not work if the necessary kernel modules are not present, only available as non-loaded modules, or are disabled in WSL2.

- **IPv6 Experimental Support:**
  IPv6 support in WSL2 is experimental and may require enabling mirrored mode or using Windows 11. If you encounter errors related to IPv6, disable IPv6 in Cilium during installation (`cilium install --set ipv6.enabled=false`).

- **Nested Virtualization and Performance:**
  WSL2 virtualizes the Linux environment, which may impact performance or limit Cilium observability features compared to native Linux hosts. Multi-node cluster networking may behave differently from bare metal or VM-based clusters.

- **Networking/Egress Limitations:**
  Host-to-pod, pod-to-pod, and multi-node networking may not exactly replicate a native Linux environment due to the way WSL2 provides network interfaces.

- **Module Loading Caveats:**
  Some kernel features may be present only as loadable modules (`m`) rather than built-in (`y`). In rare cases, modules may not be loaded automatically, requiring manual intervention. Use `lsmod` and check `/proc/config.gz` for troubleshooting.

- **Other Known Issues:**
  - TProxy and some other advanced Netfilter features may require manual configuration or remain unsupported.
  - WSL2 on Windows Home has certain restrictions due to lack of Hyper-V.

**Recommendation:**  
Always use the latest WSL2 kernel (`wsl --update`) and Windows 11 for maximum compatibility. If you encounter feature-specific errors during Cilium setup, review the Cilium logs and kernel module availability.





