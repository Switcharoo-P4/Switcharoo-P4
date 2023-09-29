#ifndef _BLOOM_INGRESS_PARSER_
#define _BLOOM_INGRESS_PARSER_

parser BloomIngressParser(packet_in pkt, out bloom_ingress_headers_t hdr, out bloom_ingress_metadata_t meta,
                          out ingress_intrinsic_metadata_t ig_intr_md) {
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.has_swap = 0;
        meta.l4_lookup = {0, 0};

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
            cuckoo_ops_t.INSERT: parse_cuckoo_counter;
            cuckoo_ops_t.WAIT: parse_cuckoo_counter;
            cuckoo_ops_t.NOP: parse_ipv4;
            cuckoo_ops_t.SWAPPED: parse_swap_entry;
            default: reject;
        }
    }
    
    state parse_cuckoo_counter {
        pkt.extract(hdr.cuckoo_counter);
        transition select(hdr.cuckoo_counter.has_swap) {
            1: parse_carry_swap_entry;
            default: parse_ipv4;
        }
    }

    state parse_swap_entry {
        pkt.extract(hdr.swap_entry);
        transition select(hdr.swap_entry.has_swap) {
            1: parse_carry_swap_entry;
            default: parse_ipv4;
        }
    }

    state parse_carry_swap_entry {
        meta.has_swap = 1;
        
        pkt.extract(hdr.carry_swap_entry);

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
            (0, _): accept;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l4_lookup = {hdr.tcp.src_port, hdr.tcp.dst_port};
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_lookup = {hdr.udp.src_port, hdr.udp.dst_port};
        transition accept;
    }
}

control BloomIngressDeparser(packet_out pkt, inout bloom_ingress_headers_t hdr, in bloom_ingress_metadata_t meta,
                             in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == SWAP_MIRROR) {
            mirror.emit<swap_mirror_h>(
                meta.mirror_session,
                {
                    meta.swap_mirror.op
                }
            );
        }

        pkt.emit(hdr);
    }
}

#endif /* _BLOOM_INGRESS_PARSER_ */