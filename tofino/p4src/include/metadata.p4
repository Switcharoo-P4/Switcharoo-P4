#ifndef _METADATA_
#define _METADATA_

#include "types.p4"

/* Cuckoo Pipe */
struct cuckoo_ingress_metadata_t {
    bit<1> first_frag;
    l4_lookup_t l4_lookup;
}

struct cuckoo_egress_metadata_t {
    swap_mirror_h swap_mirror;
}

/* Bloom Pipe */
struct bloom_ingress_metadata_t {
    bit<1> has_swap;
    l4_lookup_t l4_lookup; 
    MirrorId_t mirror_session;
    swap_mirror_h swap_mirror;
}

struct bloom_egress_metadata_t {
}

#endif /* _METADATA_ */