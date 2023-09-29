#ifndef _CUCKOO_INGRESS_PARSER_
#define _CUCKOO_INGRESS_PARSER_

#include "../../include/configuration.p4"

parser CuckooIngressParser(packet_in pkt, out cuckoo_ingress_headers_t hdr,
                           out cuckoo_ingress_metadata_t meta, out ingress_intrinsic_metadata_t ig_intr_md) {
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.first_frag = 0;
        meta.l4_lookup = {0, 0};
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.CUCKOO: parse_cuckoo_op;
            default: accept;
        }
    }

    state parse_cuckoo_op {
        pkt.extract(hdr.cuckoo_op);
        transition select(hdr.cuckoo_op.op) {
            cuckoo_ops_t.INSERT: parse_cuckoo_counter;
            cuckoo_ops_t.SWAP: parse_swap_entry;
            cuckoo_ops_t.LOOKUP: parse_cuckoo_counter;
            default: reject;
        }
    }

    state parse_cuckoo_counter {
        pkt.extract(hdr.cuckoo_counter);
        transition parse_ipv4;
    }

    state parse_swap_entry {
        pkt.extract(hdr.swap_entry);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5: parse_ipv4_no_options;
            6 &&& 0xE: parse_ipv4_options;
            8 &&& 0x8: parse_ipv4_options;
            default: reject;
        }
    }

    state parse_ipv4_options {
        pkt.extract(hdr.ipv4_options, ((bit<32>)hdr.ipv4.ihl - 5) * 32);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            (0, ip_proto_t.TCP): parse_tcp;
            (0, ip_proto_t.UDP): parse_udp;
            (0, _): parse_first_fragment;
            default: parse_first_fragment;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l4_lookup = {hdr.tcp.src_port, hdr.tcp.dst_port};
        transition parse_first_fragment;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_lookup = {hdr.udp.src_port, hdr.udp.dst_port};
        transition parse_first_fragment;
    }
    
    state parse_first_fragment {
        meta.first_frag = 1;
        transition accept;
    }
}

control CuckooIngressDeparser(packet_out pkt, inout cuckoo_ingress_headers_t hdr,
                              in cuckoo_ingress_metadata_t meta,
                              in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

#endif /* _CUCKOO_INGRESS_PARSER_ */