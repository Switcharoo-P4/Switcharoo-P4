/* -*- P4_16 -*- */

#include "../include/configuration.p4"
#include "../include/headers.p4"
#include "../include/types.p4"
#include "../include/metadata.p4"

#include "common/stats_registers.p4"

/* INGRESS */
control CuckooIngress(inout cuckoo_ingress_headers_t hdr, inout cuckoo_ingress_metadata_t meta,
                     in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {                        
    Register<bit<32>, _>(TABLE_SIZE) table_1_1;
    Register<bit<32>, _>(TABLE_SIZE) table_1_2;
    Register<bit<32>, _>(TABLE_SIZE) table_1_3;
    Register<bit<16>, _>(TABLE_SIZE) table_1_4;
    Register<bit<32>, _>(TABLE_SIZE) table_1_5;
    Register<bit<16>, _>(TABLE_SIZE) table_1_6;

    bit<32> table_1_1_entry = 0;
    bit<32> table_1_2_entry = 0;
    bit<32> table_1_3_entry = 0;
    bit<16> table_1_4_entry = 0;
    bit<32> table_1_5_entry = 0;
    bit<16> table_1_6_entry = 0;

    Register<bit<32>, _>(TABLE_SIZE) table_2_1;
    Register<bit<32>, _>(TABLE_SIZE) table_2_2;
    Register<bit<32>, _>(TABLE_SIZE) table_2_3;
    Register<bit<16>, _>(TABLE_SIZE) table_2_4;
    Register<bit<32>, _>(TABLE_SIZE) table_2_5;
    Register<bit<16>, _>(TABLE_SIZE) table_2_6;

    bit<32> key_1 = 0;
    bit<32> key_2 = 0;
    bit<32> ports = 0;
    bit<16> ip_flow_id = 0;
    bit<32> entry_ts = 0;
    bit<16> entry_ts_2 = 0;

    /* TABLE 1 */ 
    /* Lookup Actions */
    RegisterAction<bit<32>, _, bool>(table_1_1) table_1_1_lookup_action = {
        void apply(inout bit<32> value, out bool read_value) {
            if (hdr.ipv4.src_addr == value) {
                read_value = true;
            } else {
                read_value = false;
            }
        }
    };

    RegisterAction<bit<32>, _, bool>(table_1_2) table_1_2_lookup_action = {
        void apply(inout bit<32> value, out bool read_value) {
            if (hdr.ipv4.dst_addr == value) {
                read_value = true;
            } else {
                read_value = false;
            }
        }
    };

    /* Swap Actions */
    RegisterAction<bit<32>, _, bit<32>>(table_1_1) table_1_1_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            value = key_1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_1_2) table_1_2_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            value = key_2;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_1_3) table_1_3_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            value = ports;
        }
    };
    
    RegisterAction<bit<16>, _, bit<16>>(table_1_4) table_1_4_swap = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;

            value = ip_flow_id;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_1_5) table_1_5_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            bit<32> difference = ig_prsr_md.global_tstamp[31:0] - value;
            if (difference > ENTRY_TIMEOUT) {
                read_value = 0;
            } else {
                read_value = value;
            }

            value = entry_ts;
        }
    };

    RegisterAction<bit<16>, _, bit<16>>(table_1_6) table_1_6_swap = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            bit<16> difference = ig_prsr_md.global_tstamp[47:32] - value;
            if (difference == 0) {
                read_value = value;
            } else {
                read_value = 0;
            }

            value = entry_ts_2;
        }
    };

    /* TABLE 2 */
    /* Lookup Actions */
    RegisterAction<bit<32>, _, bool>(table_2_1) table_2_1_lookup_action = {
        void apply(inout bit<32> value, out bool read_value) {
            if (hdr.ipv4.src_addr == value) {
                read_value = true;
            } else {
                read_value = false;
            }
        }
    };

    RegisterAction<bit<32>, _, bool>(table_2_2) table_2_2_lookup_action = {
        void apply(inout bit<32> value, out bool read_value) {
            if (hdr.ipv4.dst_addr == value) {
                read_value = true;
            } else {
                read_value = false;
            }
        }
    };

    /* Swap Actions */
    RegisterAction<bit<32>, _, bit<32>>(table_2_1) table_2_1_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            value = table_1_1_entry;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_2_2) table_2_2_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            value = table_1_2_entry;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_2_3) table_2_3_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            value = table_1_3_entry;
        }
    };

    RegisterAction<bit<16>, _, bit<16>>(table_2_4) table_2_4_swap = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;

            value = table_1_4_entry;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_2_5) table_2_5_swap = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            bit<32> difference = ig_prsr_md.global_tstamp[31:0] - value;
            if (difference > ENTRY_TIMEOUT) {
                read_value = 0;
            } else {
                read_value = value;
            }

            value = table_1_5_entry;
        }
    };

    RegisterAction<bit<16>, _, bit<16>>(table_2_6) table_2_6_swap = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            bit<16> difference = ig_prsr_md.global_tstamp[47:32] - value;
            if (difference == 0) {
                read_value = value;
            } else {
                read_value = 0;
            }

            value = table_1_6_entry;
        }
    };

    /* STATS REGISTERS */
    RegisterAction<bit<32>, _, bit<32>>(cuckoo_recirculated_packets) cuckoo_recirculated_packets_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(insertions_counter) insertions_counter_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(expired_entry_table_1) expired_entry_table_1_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(expired_entry_table_2) expired_entry_table_2_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_2_match_counter) table_2_match_counter_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(table_1_match_counter) table_1_match_counter_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(swap_creation) swap_creation_increment = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };
    
    /* Hash Definitions */
    Hash<bit<CUCKOO_HASH_BITS>>(HashAlgorithm_t.CRC16) hash_table_1;

    CRCPolynomial<bit<CUCKOO_HASH_BITS>>(
        coeff    = 0x0589,
        reversed = false,
        msb      = false,
        extended = false,
        init     = 0x0000,
        xor      = 0x0001
    ) poly_crc_16_dect;

    CRCPolynomial<bit<CUCKOO_HASH_BITS>>(
        coeff    = 0x0589,
        reversed = false,
        msb      = false,
        extended = false,
        init     = 0x0000,
        xor      = 0x0001
    ) poly_crc_16_dect2;

    Hash<bit<CUCKOO_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_dect) hash_table_2;
    Hash<bit<CUCKOO_HASH_BITS>>(HashAlgorithm_t.CUSTOM, poly_crc_16_dect2) hash_table_2_recirculate;

    #include "../include/recirculation_actions.p4"

    /* Logic to get a flow ID */
    Random<bit<2>>() flow_id_random_gen;
    bit<2> select_flow_id_index = flow_id_random_gen.get();    
    action assign_ipv4_identification(bit<16> flow_id) {
        ip_flow_id = flow_id;
    }

    @ternary(1)
    table select_flow_id {
        key = {
            select_flow_id_index: exact;
        }
        actions = {
            assign_ipv4_identification;
        }
        size = 4;
        const entries = {
            0: assign_ipv4_identification(0xFFFF);
            1: assign_ipv4_identification(0xEEEE);
            2: assign_ipv4_identification(0xDDDD);
            3: assign_ipv4_identification(0xCCCC);
        }
    }

    /* Port selections */
    /* Bloom Port Selection */
    bit<9> original_ingress_port = hdr.ethernet.dst_addr[24:16];
    @ternary(1)
    table select_bloom_recirculation_port {
        key = {
            hdr.cuckoo_op.op: exact;
            original_ingress_port: exact;
        }
        actions = {
            recirculate_wait_ip1_to_bloom;
            recirculate_wait_ip2_to_bloom;
            recirculate_wait_ip3_to_bloom;
            recirculate_wait_ip4_to_bloom;
            recirculate_insert_ip1_to_bloom;
            recirculate_insert_ip2_to_bloom;
            recirculate_insert_ip3_to_bloom;
            recirculate_insert_ip4_to_bloom;
            recirculate_swapped_to_bloom;
            recirculate_nop_ip1_to_bloom;
            recirculate_nop_ip2_to_bloom;
            recirculate_nop_ip3_to_bloom;
            recirculate_nop_ip4_to_bloom;
        }
        size = 16;
        const entries = {
            (cuckoo_ops_t.WAIT, INGRESS_PORT_1): recirculate_wait_ip1_to_bloom();
            (cuckoo_ops_t.WAIT, INGRESS_PORT_2): recirculate_wait_ip2_to_bloom();
            (cuckoo_ops_t.WAIT, INGRESS_PORT_3): recirculate_wait_ip3_to_bloom();
            (cuckoo_ops_t.WAIT, INGRESS_PORT_4): recirculate_wait_ip4_to_bloom();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_1): recirculate_insert_ip1_to_bloom();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_2): recirculate_insert_ip2_to_bloom();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_3): recirculate_insert_ip3_to_bloom();
            (cuckoo_ops_t.INSERT, INGRESS_PORT_4): recirculate_insert_ip4_to_bloom();
            (cuckoo_ops_t.SWAPPED, INGRESS_PORT_1): recirculate_swapped_to_bloom();
            (cuckoo_ops_t.SWAPPED, INGRESS_PORT_2): recirculate_swapped_to_bloom();
            (cuckoo_ops_t.SWAPPED, INGRESS_PORT_3): recirculate_swapped_to_bloom();
            (cuckoo_ops_t.SWAPPED, INGRESS_PORT_4): recirculate_swapped_to_bloom();
            (cuckoo_ops_t.NOP, INGRESS_PORT_1): recirculate_nop_ip1_to_bloom();
            (cuckoo_ops_t.NOP, INGRESS_PORT_2): recirculate_nop_ip2_to_bloom();
            (cuckoo_ops_t.NOP, INGRESS_PORT_3): recirculate_nop_ip3_to_bloom();
            (cuckoo_ops_t.NOP, INGRESS_PORT_4): recirculate_nop_ip4_to_bloom();
        }
    }

    apply {
        if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAP) {
            /* Information is in the swap header */
            key_1 = hdr.swap_entry.ip_src_addr;
            key_2 = hdr.swap_entry.ip_dst_addr;
            ports = hdr.swap_entry.ports;
            ip_flow_id = hdr.swap_entry.entry_value;
            entry_ts = hdr.swap_entry.ts;
            entry_ts_2 = hdr.swap_entry.ts_2;
        } else {
            /* Get everything from the original headers */
            key_1 = hdr.ipv4.src_addr;
            key_2 = hdr.ipv4.dst_addr;
            ports = meta.l4_lookup.src_port ++ meta.l4_lookup.dst_port;
            entry_ts = ig_prsr_md.global_tstamp[31:0];
            entry_ts_2 = ig_prsr_md.global_tstamp[47:32];
        }
        
        bit<CUCKOO_HASH_BITS> idx_table_1 = hash_table_1.get({key_1, key_2, ports});

        if (hdr.cuckoo_op.isValid() && (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT || hdr.cuckoo_op.op == cuckoo_ops_t.SWAP)) {
            /* Insert the value in Table 1. If the entry is not empty, swap the old value in Table 2 */
            cuckoo_recirculated_packets_increment.execute(0);
            
            if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
                /* First recirculation, compute a new flow ID */
                select_flow_id.apply();

                insertions_counter_increment.execute(0);
            }

            bool to_swap_1 = false;

            table_1_1_entry = table_1_1_swap.execute(idx_table_1);
            table_1_2_entry = table_1_2_swap.execute(idx_table_1);
            table_1_3_entry = table_1_3_swap.execute(idx_table_1);
            table_1_4_entry = table_1_4_swap.execute(idx_table_1);
            table_1_5_entry = table_1_5_swap.execute(idx_table_1);
            table_1_6_entry = table_1_6_swap.execute(idx_table_1);
            
            if (table_1_6_entry != 0) {
                /* First 16bits of timestamp are equal, check last 32bits */
                if (table_1_5_entry != 0) {
                    /* Entry not expired, need to check if we must swap it to Table 2 */
                    if (table_1_1_entry != 0 && table_1_1_entry != key_1) {
                        to_swap_1 = true;
                    } else if (table_1_2_entry != 0 && table_1_2_entry != key_2) {
                        to_swap_1 = true;
                    } else if (table_1_3_entry != 0 && table_1_3_entry != ports) {
                        to_swap_1 = true;
                    }
                } else {
                    expired_entry_table_1_increment.execute(0);
                }
            } else {
                expired_entry_table_1_increment.execute(0);
            }
            
            if (to_swap_1) {
                /* Table 1 entry was not empty and not expired */
                bool to_swap_2 = false;

                bit<CUCKOO_HASH_BITS> idx_table_2_r = hash_table_2_recirculate.get({table_1_1_entry, table_1_2_entry, table_1_3_entry});
                bit<32> table_2_1_entry = table_2_1_swap.execute(idx_table_2_r);
                bit<32> table_2_2_entry = table_2_2_swap.execute(idx_table_2_r);
                bit<32> table_2_3_entry = table_2_3_swap.execute(idx_table_2_r);
                hdr.carry_swap_entry.entry_value = table_2_4_swap.execute(idx_table_2_r);
                hdr.carry_swap_entry.ts = table_2_5_swap.execute(idx_table_2_r);
                hdr.carry_swap_entry.ts_2 = table_2_6_swap.execute(idx_table_2_r);
                
                if (hdr.carry_swap_entry.ts_2 != 0) {
                    /* First 16bits of timestamp are equal, check last 32bits */
                    if (hdr.carry_swap_entry.ts != 0) {
                         /* Entry not expired, need to check if we must swap it to Table 1 */
                        if (table_2_1_entry != 0) {
                            to_swap_2 = true;
                        } else if (table_2_2_entry != 0) {
                            to_swap_2 = true;
                        } else if (table_2_3_entry != 0) {
                            to_swap_2 = true;
                        }
                    } else {
                        expired_entry_table_2_increment.execute(0);
                    }
                } else {
                    expired_entry_table_2_increment.execute(0);
                }
                
                if (to_swap_2) {
                    swap_creation_increment.execute(0);

                    /* Table 2 entry was not empty and not expired */
                    if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
                        /* If it is the first recirculation of this packet, we should send the original one to the
                        bloom filter with swap.op = WAIT and append a swap_entry header which will create a copy on the Bloom to continue swapping */
                        hdr.ipv4.identification = ip_flow_id;

                        hdr.cuckoo_op.op = cuckoo_ops_t.WAIT;
                        hdr.cuckoo_counter.recirc_counter = 0;

                        hdr.cuckoo_counter.has_swap = 1;

                        hdr.carry_swap_entry.setValid();
                        hdr.carry_swap_entry.ip_src_addr = table_2_1_entry;
                        hdr.carry_swap_entry.ip_dst_addr = table_2_2_entry;
                        hdr.carry_swap_entry.ports = table_2_3_entry;
                    } else if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAP) {
                        /* If it's already a mirrored packet, send the original packet to the bloom with swap.op = SWAPPED,
                        so it will decrease the corresponding bloom entry, and append a swap_entry header which will create a copy on the Bloom to continue swapping */
                        hdr.cuckoo_op.op = cuckoo_ops_t.SWAPPED;

                        hdr.swap_entry.has_swap = 1;

                        hdr.carry_swap_entry.setValid();
                        hdr.carry_swap_entry.ip_src_addr = table_2_1_entry;
                        hdr.carry_swap_entry.ip_dst_addr = table_2_2_entry;
                        hdr.carry_swap_entry.ports = table_2_3_entry;
                    }
                } else {
                    /* Table 2 entry was expired */
                    if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
                        /* Send the packet to the bloom filter with swap.op = WAIT. It will be recircultated on the Bloom Pipe
                        until it is its turn to be sent out  */
                        hdr.ipv4.identification = ip_flow_id;

                        hdr.cuckoo_op.op = cuckoo_ops_t.WAIT;
                        hdr.cuckoo_counter.recirc_counter = 0;
                    } else if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAP) {
                        /* Send the packet to the Bloom Pipe with swap.op = SWAPPED, so it will decrease the bloom entry */
                        hdr.cuckoo_op.op = cuckoo_ops_t.SWAPPED;
                        ig_tm_md.packet_color = 0;
                    }
                }
            } else {
                /* Table 1 was expired */
                if (hdr.cuckoo_op.op == cuckoo_ops_t.INSERT) {
                    /* Send the packet to the bloom filter with swap.op = WAIT. It will be recircultated on the Bloom Pipe
                    until it is its turn to be sent out  */
                    hdr.ipv4.identification = ip_flow_id;
                    
                    hdr.cuckoo_op.op = cuckoo_ops_t.WAIT;
                    hdr.cuckoo_counter.recirc_counter = 0;
                } else if (hdr.cuckoo_op.op == cuckoo_ops_t.SWAP) {
                    /* Send the packet to the Bloom Pipe with swap.op = SWAPPED, so it will decrease the bloom entry */
                    hdr.cuckoo_op.op = cuckoo_ops_t.SWAPPED;
                    ig_tm_md.packet_color = 0;
                }
            }
        } else if ((hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.LOOKUP) || (hdr.ipv4.isValid() && meta.first_frag == 1)) {
            if (hdr.ethernet.ether_type == ether_type_t.IPV4) {
                /* This is used by the parser to check if there are cuckoo headers */
                /* Also sets the recirculation counter (last 16bits of dst mac address) */
                /* And the original ingress port (bits 24-16 of dst mac address) */
                hdr.ethernet.ether_type = ether_type_t.CUCKOO;
                hdr.ethernet.dst_addr[15:0] = 0x0;
                hdr.ethernet.dst_addr[24:16] = ig_intr_md.ingress_port;
                original_ingress_port = ig_intr_md.ingress_port;
            }

            bool table_1_match = false;
            bool table_2_match = false;

            /* Lookup in Table 1 */
            bool table_1_1_lookup = table_1_1_lookup_action.execute(idx_table_1);
            bool table_1_2_lookup = table_1_2_lookup_action.execute(idx_table_1);
            if (table_1_1_lookup && table_1_2_lookup) {
                bit<32> table_1_3_lookup = table_1_3.read(idx_table_1);
                if (table_1_3_lookup == ports) {
                    table_1_match = true;
                    table_1_5.write(idx_table_1, ig_prsr_md.global_tstamp[31:0]);
                    table_1_6.write(idx_table_1, ig_prsr_md.global_tstamp[47:32]);
                }
            }
           
            if (table_1_match) {
                /* Do something with the value. In this example we assign it to the IPv4 ID field. */
                hdr.ipv4.identification = table_1_4.read(idx_table_1);

                table_1_match_counter_increment.execute(0);

                if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.LOOKUP) {
                    /* Lookup was successful after a recirculation, send the packet to the Bloom Pipe with swap.op = WAIT */
                    hdr.cuckoo_op.op = cuckoo_ops_t.WAIT;
                    hdr.cuckoo_counter.recirc_counter = 0;
                } else {
                    /* This packet never recirculated, send it to the Bloom Pipe with swap.op = NOP */
                    hdr.cuckoo_op.setValid();
                    hdr.cuckoo_op.op = cuckoo_ops_t.NOP;
                }
            } else {
                /* Lookup in Table 2 */ 
                bit<CUCKOO_HASH_BITS> idx_table_2 = hash_table_2.get({key_1, key_2, ports});

                bool table_2_1_lookup = table_2_1_lookup_action.execute(idx_table_2);
                bool table_2_2_lookup = table_2_2_lookup_action.execute(idx_table_2);
                if (table_2_1_lookup && table_2_2_lookup) {
                    bit<32> table_2_3_lookup = table_2_3.read(idx_table_2);
                    if (table_2_3_lookup == ports) {
                        table_2_match = true;
                        table_2_5.write(idx_table_2, ig_prsr_md.global_tstamp[31:0]);
                        table_2_6.write(idx_table_2, ig_prsr_md.global_tstamp[47:32]);
                    }
                }

                if (table_2_match) {
                    /* Do something with the value. In this example we assign it to the IPv4 ID field. */
                    hdr.ipv4.identification = table_2_4.read(idx_table_2);
                    
                    table_2_match_counter_increment.execute(0);

                    if (hdr.cuckoo_op.isValid() && hdr.cuckoo_op.op == cuckoo_ops_t.LOOKUP) {
                        /* Lookup was successful after a recirculation, send the packet to the Bloom Pipe with swap.op = WAIT */
                        hdr.cuckoo_op.op = cuckoo_ops_t.WAIT;
                        hdr.cuckoo_counter.recirc_counter = 0;
                    } else {
                        /* This packet never recirculated, send it to the Bloom Pipe with swap.op = NOP */
                        hdr.cuckoo_op.setValid();
                        hdr.cuckoo_op.op = cuckoo_ops_t.NOP;
                    }
                } else {
                    /* Lookup failed, recirculate the packet to insert it in the table */
                    hdr.cuckoo_op.setValid();
                    hdr.cuckoo_op.op = cuckoo_ops_t.INSERT;
                    hdr.cuckoo_counter.setValid();
                    hdr.cuckoo_counter.recirc_counter = 0;
                    ig_tm_md.packet_color = 0;
                } 
            }
        }

        select_bloom_recirculation_port.apply();
    }
}

/* EGRESS */
control CuckooEgress(inout cuckoo_egress_headers_t hdr, inout cuckoo_egress_metadata_t meta,
                    in egress_intrinsic_metadata_t eg_intr_md, in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
                    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
                    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {
        /* Packets received here are copies of packets with this header sequence: */
        /* Swap Mirror | Ethernet | Cuckoo Op | (Swap Entry OR Cuckoo Counter) | Carry Swap Entry */
        /* We only need Swap Mirror info in the Cuckoo Pipe, so we copy data in the real Swap Entry and remove everything else */
        hdr.cuckoo_op.setValid();
        hdr.cuckoo_op.op = meta.swap_mirror.op;

        hdr.swap_entry.setValid();
        hdr.swap_entry.ip_src_addr = hdr.carry_swap_entry.ip_src_addr;
        hdr.swap_entry.ip_dst_addr = hdr.carry_swap_entry.ip_dst_addr;
        hdr.swap_entry.ports = hdr.carry_swap_entry.ports;
        hdr.swap_entry.entry_value = hdr.carry_swap_entry.entry_value;
        hdr.swap_entry.ts = hdr.carry_swap_entry.ts;
        hdr.swap_entry.ts_2 = hdr.carry_swap_entry.ts_2;
        hdr.swap_entry.has_swap = 0;

        hdr.cuckoo_counter.setInvalid();

        hdr.carry_swap_entry.setInvalid();
    }
}