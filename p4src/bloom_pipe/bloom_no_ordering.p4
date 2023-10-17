/* -*- P4_16 -*- */

#include "../include/configuration.p4"
#include "../include/headers.p4"
#include "../include/types.p4"
#include "../include/metadata.p4"

#include "common/stats_registers.p4"

/* INGRESS */
control BloomIngress(inout bloom_ingress_headers_t hdr, inout bloom_ingress_metadata_t meta,
                     in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Register<bit<16>, _>(SWAP_BLOOM_FILTER_SIZE) swap_transient;
    Register<bit<16>, _>(SWAP_BLOOM_FILTER_SIZE) swapped_transient;
    Register<bloom_filter_t, _>(BLOOM_FILTER_SIZE) ordering_bf;
    Register<bit<16>, _>(BLOOM_FILTER_SIZE) flow_count;

    /* SWAP TRANSIENT */ 
    /* Lookup Actions */
    RegisterAction<bit<16>, _, bit<16>>(swap_transient) swap_transient_increment = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            value = value |+| 1;
        }
    };

    /* SWAPPED TRANSIENT */ 
    /* Lookup Actions */
    RegisterAction<bit<16>, _, bit<16>>(swapped_transient) swapped_transient_increment = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            value = value |+| 1;
        }
    };

    /* ORDERING BF */ 
    /* Lookup Actions */
    RegisterAction<bloom_filter_t, _, bit<16>>(ordering_bf) ordering_bf_lookup = {
        void apply(inout bloom_filter_t value, out bit<16> read_value) {
            if (value.bloom_counter != 0) {
                value.bloom_counter = value.bloom_counter |+| 1;
            }

            read_value = value.bloom_counter;
        }
    };

    /* Increment/Decrement Actions */
    RegisterAction<bloom_filter_t, _, bit<16>>(ordering_bf) ordering_bf_read_and_increment = {
        void apply(inout bloom_filter_t value, out bit<16> read_value) {
            if (value.bloom_counter == 0) {
                value.packet_to_send_out = 0;
            }

            read_value = value.bloom_counter;
            value.bloom_counter = value.bloom_counter |+| 1;
        }
    };

    RegisterAction<bloom_filter_t, _, bit<16>>(ordering_bf) decrement_ordering_bf_and_packet_to_send_out_lookup = {
        void apply(inout bloom_filter_t value, out bit<16> read_value) {
            read_value = value.packet_to_send_out;
            if (value.packet_to_send_out == hdr.cuckoo_counter.assigned_counter) {
                value.packet_to_send_out = value.packet_to_send_out |+| 1; 
                value.bloom_counter = value.bloom_counter |-| 1; 
            } else if (hdr.cuckoo_counter.recirc_counter == MAX_LOOPS_WAIT) {
                value.packet_to_send_out = hdr.cuckoo_counter.assigned_counter |+| 1; 
                value.bloom_counter = value.bloom_counter |-| 2;
            }
        }
    };

    /* FLOW COUNT */ 
    /* Init/Increment Actions */
    RegisterAction<bit<16>, _, bit<16>>(flow_count) flow_count_init = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = 0;
            value = 1;
        }
    };
    
    RegisterAction<bit<16>, _, bit<16>>(flow_count) flow_count_read_and_increment = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;
            value = value + 1;
        }
    };

    /* STATS REGISTERS */
    RegisterAction<bit<32>, _, bit<32>>(bloom_packets_sent_out) bloom_packets_sent_out_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(wait_max_loops_on_bloom) wait_max_loops_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(insert_max_loops_on_bloom) insert_max_loops_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(from_insert_to_lookup_swap) from_insert_to_lookup_swap_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(from_insert_to_lookup_bloom) from_insert_to_lookup_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(wait_counter_on_bloom) wait_counter_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(insert_counter_on_bloom) insert_counter_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(swap_counter_on_bloom) swap_counter_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(swapped_counter_on_bloom) swapped_counter_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(nop_counter_on_bloom) nop_counter_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(lookup_counter_on_bloom) lookup_counter_on_bloom_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(swap_dropped) swap_dropped_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(from_nop_to_wait) from_nop_to_wait_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    #include "../include/recirculation_actions.p4"

    action send(PortId_t port_number) {
        ig_tm_md.ucast_egress_port = port_number;
        ig_tm_md.bypass_egress = 0x1;
        ig_dprsr_md.drop_ctl = 0x0;
    }

    @ternary(1)
    table forward {
        key = {
            hdr.ipv4.identification: exact;
        }
        actions = {
            send;
        }
        size = 1024;
    }

    /* Port selections */
    /* Cuckoo Port Selection */
    bit<9> original_ingress_port = hdr.ethernet.dst_addr[24:16];
    @ternary(1)
    table select_cuckoo_recirculation_port {
        key = {
            hdr.cuckoo_op.op: exact;
            original_ingress_port: exact;
        }
        actions = {
            recirculate_insert_ip1_to_cuckoo;
            recirculate_insert_ip2_to_cuckoo;
            recirculate_insert_ip3_to_cuckoo;
            recirculate_insert_ip4_to_cuckoo;
            recirculate_lookup_ip1_to_cuckoo;
            recirculate_lookup_ip2_to_cuckoo;
            recirculate_lookup_ip3_to_cuckoo;
            recirculate_lookup_ip4_to_cuckoo;
        }
        size = 8;
        const entries = {
            (cuckoo_ops_t.INSERT, INGRESS_PORT_1): recirculate_insert_ip1_to_cuckoo();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_2): recirculate_insert_ip2_to_cuckoo();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_3): recirculate_insert_ip3_to_cuckoo();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_4): recirculate_insert_ip4_to_cuckoo();
            (cuckoo_ops_t.LOOKUP, INGRESS_PORT_1): recirculate_lookup_ip1_to_cuckoo();
            (cuckoo_ops_t.LOOKUP, INGRESS_PORT_2): recirculate_lookup_ip2_to_cuckoo();
            (cuckoo_ops_t.LOOKUP, INGRESS_PORT_3): recirculate_lookup_ip3_to_cuckoo();
            (cuckoo_ops_t.LOOKUP, INGRESS_PORT_4): recirculate_lookup_ip4_to_cuckoo();
        }
    }

    apply {
        if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
            insert_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.NOP) {
            nop_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED) {
            swapped_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.LOOKUP) {
            lookup_counter_on_bloom_increment.execute(0);
        }
        
        if (hdr.cuckoo_op.isValid() && (meta.has_swap == 1 || hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED)) {
            if (meta.has_swap == 1) {
                /* This packet carries a swap entry */
                swap_counter_on_bloom_increment.execute(0);

                /* Clone and send to Cukoo pipe */
                ig_dprsr_md.mirror_type = SWAP_MIRROR;
                meta.mirror_session = SWAP_MIRROR_SESSION;
                meta.swap_mirror.op = cuckoo_ops_t.SWAP;

                hdr.carry_swap_entry.setInvalid();

                hdr.cuckoo_counter.has_swap = 0;

                hdr.swap_entry.has_swap = 0;
            }

            if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED) {
                /* swap.op = SWAPPED must be dropped after updating the swapped_transient structure */
                ig_dprsr_md.drop_ctl = 0x1;
            }
        }

        if (hdr.cuckoo_op.op == cuckoo_ops_t.WAIT || hdr.cuckoo_op.op == cuckoo_ops_t.NOP) {
            bloom_packets_sent_out_increment.execute(0);

            hdr.cuckoo_op.setInvalid();
            hdr.cuckoo_counter.setInvalid();

            /* Restore original EtherType before sending out */
            hdr.ethernet.ether_type = ether_type_t.IPV4;
            
            forward.apply();
        } else {
            hdr.ethernet.dst_addr[15:0] = hdr.ethernet.dst_addr[15:0] + 1;

            select_cuckoo_recirculation_port.apply();   
        }
    }
}

/* EGRESS */
control BloomEgress(inout bloom_egress_headers_t hdr, inout bloom_egress_metadata_t meta,
                    in egress_intrinsic_metadata_t eg_intr_md,
                    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
                    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
                    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {
    }
}