/* `bastion doctor [-c file]`: what this host offers Bastion, with recommended values. It only
 * reads (/proc, /sys, getrlimit, and probes that create and free an io_uring, a socket or a BPF
 * program) and never changes a setting. Exit status: 0, or 1 when a `require` in the config
 * would fail on this host, or 2 for a usage or config error. */
#ifndef BST_OPS_DOCTOR_H
#define BST_OPS_DOCTOR_H

int bst_doctor_main(int argc, char **argv);

#endif
