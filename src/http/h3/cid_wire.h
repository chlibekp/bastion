/* The wire layout of Bastion's QUIC connection IDs, shared by the C code (cid.c) and the
 * sk_reuseport program (xdp/reuseport_quic.bpf.c), which is built for the BPF target and can
 * include nothing else. Defines only.
 *
 *   byte 0      random
 *   bytes 1-2   worker slot, big endian, XOR bytes 3-4
 *   bytes 3-15  random
 *
 * The slot is masked by random bytes of the same ID, so two IDs of one connection share no fixed
 * bytes on the wire; anyone who knows this layout can still read the slot, which only says which
 * worker of this server holds the connection (RFC 9000 section 9.5 asks that IDs not be linkable
 * by an observer; QUIC-LB's plaintext mode makes the same trade). */
#ifndef BST_H3_CID_WIRE_H
#define BST_H3_CID_WIRE_H

#define BST_CID_LEN 16       /* every connection ID Bastion issues */
#define BST_CID_SLOT_OFF 1   /* the masked slot */
#define BST_CID_MASK_OFF 3   /* the mask */
#define BST_CID_MIN_LEN 5    /* the shortest ID that can carry a slot */

/* QUIC packet header offsets inside the UDP payload (RFC 9000 section 17). */
#define BST_QUIC_LONG_DCID_LEN_OFF 5 /* first byte, 4-byte version, then the DCID length */
#define BST_QUIC_LONG_DCID_OFF 6
#define BST_QUIC_SHORT_DCID_OFF 1

#endif
