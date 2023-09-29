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
    
    /* Hash Definitions */
    CRCPolynomial<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(
        coeff    = 0x1021,
        reversed = true,
        msb      = false,
        extended = false,
        init     = 0xB2AA,
        xor      = 0x0000
    ) poly_crc_16_riello;

    CRCPolynomial<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(
        coeff    = 0x1021,
        reversed = true,
        msb      = false,
        extended = false,
        init     = 0xB2AA,
        xor      = 0x0000
    ) poly_crc_16_riello2;

    CRCPolynomial<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(
        coeff    = 0x1021,
        reversed = true,
        msb      = false,
        extended = false,
        init     = 0xB2AA,
        xor      = 0x0000
    ) poly_crc_16_riello3;

    CRCPolynomial<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(
        coeff    = 0x1021,
        reversed = true,
        msb      = false,
        extended = false,
        init     = 0xB2AA,
        xor      = 0x0000
    ) poly_crc_16_riello4;

    Hash<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_riello) hash_swap;
    Hash<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_riello2) hash_swap_2;
    Hash<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_riello3) hash_swapped;
    Hash<bit<SWAP_BLOOM_FILTER_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_riello4) hash_swapped_2;

    CRCPolynomial<bit<BLOOM_FILTER_HASH_BITS>>(
        coeff    = 0x1021,
        reversed = false,
        msb      = false,
        extended = false,
        init     = 0xFFFF,
        xor      = 0xFFFF
    ) poly_crc_16_genibus;
    Hash<bit<BLOOM_FILTER_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_genibus) hash_ordering_bf;

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
        if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.WAIT) {
            wait_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
            insert_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.NOP) {
            nop_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED) {
            swapped_counter_on_bloom_increment.execute(0);
        } else if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.LOOKUP) {
            lookup_counter_on_bloom_increment.execute(0);
        }
        
        bool transform_to_lookup = false;
        if (hdr.cuckoo_op.isValid() && (meta.has_swap == 1 || hdr.cuckoo_op.op == cuckoo_ops_t.INSERT || hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED)) {
            /* Handlers for transient states */
            bit<16> swap_transient_value = 0;
            bit<16> swapped_transient_value = 0;

            if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
                /* INSERT, we have to read both swap and swapped transient at the same index */
                bit<SWAP_BLOOM_FILTER_HASH_BITS> swap_transient_idx = hash_swap.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.l4_lookup.src_port ++ meta.l4_lookup.dst_port});
                
                if (hdr.ethernet.dst_addr[15:0] == MAX_LOOPS_INSERT) {
                    /* Reached the MAX_LOOPS_INSERT recirculations, the swap packet is probably lost, reset the transients */
                    swap_transient.write(swap_transient_idx, 0);
                    swapped_transient.write(swap_transient_idx, 0);

                    insert_max_loops_on_bloom_increment.execute(0);
                } else {
                    /* Read values */
                    swap_transient_value = swap_transient.read(swap_transient_idx);
                    swapped_transient_value = swapped_transient.read(swap_transient_idx);
                }
            } else if (meta.has_swap == 0 && hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED) {
                /* If it is a SWAPPED and does not carry a swap entry, update the swapped transient by increasing the value at the corresponding index */
                swapped_transient_increment.execute(hash_swapped.get({hdr.swap_entry.ip_src_addr, hdr.swap_entry.ip_dst_addr, hdr.swap_entry.ports}));
            } else if (meta.has_swap == 1) {
                /* This packet carries a swap entry */
                swap_counter_on_bloom_increment.execute(0);

                /* Clone and send to Cukoo pipe */
                ig_dprsr_md.mirror_type = SWAP_MIRROR;
                meta.mirror_session = SWAP_MIRROR_SESSION;
                meta.swap_mirror.op = cuckoo_ops_t.SWAP;

                hdr.carry_swap_entry.setInvalid();

                hdr.cuckoo_counter.has_swap = 0;

                hdr.swap_entry.has_swap = 0;

                /* Update the swap transient by increasing the value at the corresponding index */
                swap_transient_increment.execute(hash_swap_2.get({hdr.carry_swap_entry.ip_src_addr, hdr.carry_swap_entry.ip_dst_addr, hdr.carry_swap_entry.ports}));
            
                if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED) {
                    /* If it is also a SWAPPED, update the swapped transient by increasing the value at the corresponding index */
                    swapped_transient_increment.execute(hash_swapped_2.get({hdr.swap_entry.ip_src_addr, hdr.swap_entry.ip_dst_addr, hdr.swap_entry.ports}));
                }
            }

            if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAPPED) {
                /* swap.op = SWAPPED must be dropped after updating the swapped_transient structure */
                ig_dprsr_md.drop_ctl = 0x1;
            } else if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
                /* If it is an insertion packet, send it to the Cuckoo Pipe */
                if (swap_transient_value != swapped_transient_value) {
                    /* If a packet is already recirculating for insert send it to Cuckoo Pipe for lookup */
                    transform_to_lookup = true;

                    from_insert_to_lookup_swap_increment.execute(0);
                }
            }
        }

        bool increment_flow_count = false;
        bool init_flow_count = false;
        bool set_flow_count = false;
        bool to_send_out = false;

        bit<BLOOM_FILTER_HASH_BITS> ordering_bf_index = hash_ordering_bf.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.l4_lookup.src_port ++ meta.l4_lookup.dst_port});
        bit<16> ordering_bf_value;
        
        if (hdr.cuckoo_op.isValid() && (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT || hdr.cuckoo_op.op == cuckoo_ops_t.WAIT || hdr.cuckoo_op.op == cuckoo_ops_t.NOP)) {
            if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT && hdr.cuckoo_counter.is_assigned == 0) {
                /* First time in Bloom Pipe for this packet */
                ordering_bf_value = ordering_bf_read_and_increment.execute(ordering_bf_index);
        
                if (ordering_bf_value == 0) {
                    /* Bloom Filter on this entry is 0, init the flow counter */
                    init_flow_count = true;
                } else {
                    /* Bloom Filter on this entry is not 0, increment the flow counter and transform it into a lookup */ 
                    increment_flow_count = true;
                    transform_to_lookup = true;

                    from_insert_to_lookup_bloom_increment.execute(0);
                }
            } else if (hdr.cuckoo_op.op == cuckoo_ops_t.WAIT) {
                /* Packet that is waiting to be sent out */
                bit<16> packet_to_send_out_index = decrement_ordering_bf_and_packet_to_send_out_lookup.execute(ordering_bf_index);

                if (packet_to_send_out_index == hdr.cuckoo_counter.assigned_counter) {
                    /* It can go out, remove extra headers and send it */
                    hdr.cuckoo_op.setInvalid();
                    hdr.cuckoo_counter.setInvalid();
        
                    to_send_out = true;
                } else if (hdr.cuckoo_counter.recirc_counter >= MAX_LOOPS_WAIT) {
                    /* Packet recirculated too many times, send it out in any case */
                    wait_max_loops_on_bloom_increment.execute(0);

                    hdr.cuckoo_op.setInvalid();
                    hdr.cuckoo_counter.setInvalid();
        
                    to_send_out = true;
                } else {
                    /* Still not its turn, recirculate again */
                    hdr.cuckoo_counter.recirc_counter = hdr.cuckoo_counter.recirc_counter + 1;
                }
            } else if (hdr.cuckoo_op.op == cuckoo_ops_t.NOP) {
                /* Packet that did a successful lookup, check if it can be sent out */
                ordering_bf_value = ordering_bf_lookup.execute(ordering_bf_index);
                
                if (ordering_bf_value == 0) {
                    /* It can go out, remove extra headers and send it */
                    hdr.cuckoo_op.setInvalid();
                    
                    to_send_out = true;
                } else {
                    /* Still not its turn, recirculate again, changing swap.op = WAIT and passing it through the flow counter */
                    hdr.cuckoo_op.op = cuckoo_ops_t.WAIT;
                    increment_flow_count = true;

                    hdr.cuckoo_counter.setValid();
                    hdr.cuckoo_counter.recirc_counter = 0;

                    from_nop_to_wait_increment.execute(0);
                }
            }
        }
        
        if (init_flow_count && hdr.cuckoo_counter.isValid() && hdr.cuckoo_counter.is_assigned == 0) {
            hdr.cuckoo_counter.assigned_counter = flow_count_init.execute(ordering_bf_index);
            hdr.cuckoo_counter.is_assigned = 1;
        } else if (increment_flow_count && hdr.cuckoo_counter.isValid() && hdr.cuckoo_counter.is_assigned == 0) {
            hdr.cuckoo_counter.assigned_counter = flow_count_read_and_increment.execute(ordering_bf_index);
            hdr.cuckoo_counter.is_assigned = 1;
        }

        if (transform_to_lookup) {
            hdr.cuckoo_op.op = cuckoo_ops_t.LOOKUP;
        }

        if (to_send_out) {
            bloom_packets_sent_out_increment.execute(0);

            /* Restore original EtherType before sending out */
            hdr.ethernet.ether_type = ether_type_t.IPV4;
            
            forward.apply();
        } else {
            hdr.ethernet.dst_addr[15:0] = hdr.ethernet.dst_addr[15:0] + 1;

            if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.WAIT) {
                recirculate_wait_in_bloom();
            } else {
                select_cuckoo_recirculation_port.apply();
            }   
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