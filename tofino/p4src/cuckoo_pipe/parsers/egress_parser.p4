#ifndef _CUCKOO_EGRESS_PARSER_
#define _CUCKOO_EGRESS_PARSER_

#include "../../include/configuration.p4"

parser CuckooEgressParser(packet_in pkt, out cuckoo_egress_headers_t hdr, out cuckoo_egress_metadata_t meta,
                          out egress_intrinsic_metadata_t eg_intr_md) {
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);

        transition select(eg_intr_md.egress_port) {
            RECIRCULATE_PORT_SWAP_TO_CUCKOO: parse_swap_mirror;
            default: reject;
        }
    }

    state parse_swap_mirror {
        pkt.extract(meta.swap_mirror);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.CUCKOO: parse_cuckoo_op;
            default: reject;
        }
    }

    state parse_cuckoo_op {
        pkt.extract(hdr.cuckoo_op);
        transition select(hdr.cuckoo_op.op) {
            cuckoo_ops_t.WAIT: parse_cuckoo_counter;
            cuckoo_ops_t.SWAPPED: parse_swap_entry;
            default: reject;
        }
    }

    state parse_cuckoo_counter {
        pkt.extract(hdr.cuckoo_counter);
        transition select(hdr.cuckoo_counter.has_swap) {
            1: parse_carry_swap_entry;
            default: reject;
        }
    }

    state parse_swap_entry {
        pkt.extract(hdr.swap_entry);
        transition select(hdr.swap_entry.has_swap) {
            1: parse_carry_swap_entry;
            default: reject;
        }
    }

    state parse_carry_swap_entry {
        pkt.extract(hdr.carry_swap_entry);
        transition accept;
    }
}

control CuckooEgressDeparser(packet_out pkt, inout cuckoo_egress_headers_t hdr, in cuckoo_egress_metadata_t meta,
                             in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

#endif /* _CUCKOO_EGRESS_PARSER_ */