/* QUIC connection IDs that name the worker owning the connection (architecture section 4).
 *
 * Every worker has its own UDP socket in each QUIC listener's SO_REUSEPORT group. A packet for an
 * established connection must reach the worker that holds it, whatever address it now comes from
 * (NAT rebinding, a client changing networks), so the kernel cannot hash the 4-tuple: the
 * sk_reuseport program (xdp/reuseport.h) reads the slot out of the destination connection
 * ID instead. Layout: cid_wire.h. */
#ifndef BST_H3_CID_H
#define BST_H3_CID_H

#include "http/h3/cid_wire.h"

#include <stddef.h>
#include <stdint.h>

#define BST_CID_NO_SLOT UINT16_MAX /* bst_cid_slot of an ID too short to carry one */

/* Fills out[0..len-1] with a new ID for slot: the masked slot plus bytes from a CSPRNG. len is at
 * least BST_CID_MIN_LEN and at most 20 (RFC 9000). 0, or -1 when len is out of range or the
 * random generator failed (out is then unusable). */
int bst_cid_generate(uint16_t slot, uint8_t *out, size_t len);

/* The slot an ID carries, BST_CID_NO_SLOT when len is below BST_CID_MIN_LEN. Any ID of that
 * length decodes to some slot: the caller checks the range (a client-chosen Initial DCID is
 * random). */
uint16_t bst_cid_slot(const uint8_t *cid, size_t len);

#endif
