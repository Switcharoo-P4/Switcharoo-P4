#ifndef _BLOOM_EGRESS_PARSER_
#define _BLOOM_EGRESS_PARSER_

parser BloomEgressParser(packet_in pkt, out bloom_egress_headers_t hdr, out bloom_egress_metadata_t meta,
                         out egress_intrinsic_metadata_t eg_intr_md) {
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control BloomEgressDeparser(packet_out pkt, inout bloom_egress_headers_t hdr, in bloom_egress_metadata_t meta, 
                            in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

#endif /* _BLOOM_EGRESS_PARSER_ */