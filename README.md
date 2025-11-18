# A-Linux-kernel-module-that-implements-Slab-Allocator-for-network-control
A Linux kernel module that implements Slab Allocator for network control, along with eBPF and Netfilter Hook for processing incoming packets and allocating safe memory in the kernel.
-------
A Linux kernel module that implements Slab Allocator for network control, along with eBPF and Netfilter Hook for processing incoming packets and allocating safe memory in the kernel.
----
This system is suitable for:

Kernel firewalls, intrusion detection systems (NIDS), SDN controllers, high traffic analysis systems (HFT) ✅ Ultimate features:
Slab Allocator in the kernel with multiple memory classes Netfilter Hook to capture incoming eBPF packets for dynamic analysis and control of the Thread-Safe policy in the kernel Accurate tracking of memory leaks Logging capability in dmesg Application in Linux kernel 5.x and above
--------
kernel_network_slab/
├── Makefile
├── network_slab_module.c
└── network_slab_module.h
-----------
make
sudo insmod network_slab_module.ko
dmesg | tail -20

output

[NSA] Network Slab Allocator initialized.
[NSA] Network Slab Allocator Module Loaded.
[NSA] Analyzed packet: SRC: 192.168.1.100, DST: 8.8.8.8, PROTO: 6


remove modual
sudo rmmod network_slab_module
dmesg | tail -10
