/* `steering ebpf`: a BPF program on the listener's SO_REUSEPORT group that hands a connection to
 * the socket of the worker pinned to the CPU that received it (ops/numa.h has the map). It is a
 * classic BPF program (SO_ATTACH_REUSEPORT_CBPF): reading the receiving CPU and comparing it
 * against the map needs nothing eBPF adds, and it needs no bpf() syscall, no CAP_BPF and no
 * verifier. A CPU no slot is pinned to falls back to cpu modulo the socket count. */
#ifndef BST_IO_STEERING_H
#define BST_IO_STEERING_H

#include <linux/filter.h>
#include <stddef.h>

/* The program for slots sockets, slot i on CPU cpu_of(i): its length, or -1 when cap is short. */
long bst_steering_build(int slots, int (*cpu_of)(int slot), struct sock_filter *out, size_t cap);

/* Attaches the program to the group of fd (any socket of it, once bound). 0, or -errno. */
int bst_steering_attach(int fd, int slots);

#endif
