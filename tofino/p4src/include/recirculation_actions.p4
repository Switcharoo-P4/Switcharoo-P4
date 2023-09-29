action recirculate_insert_ip1_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP1_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip2_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP2_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip3_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP3_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip4_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP4_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_lookup_ip1_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_LOOKUP_IP1_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_lookup_ip2_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_LOOKUP_IP2_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_lookup_ip3_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_LOOKUP_IP3_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_lookup_ip4_to_cuckoo() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_LOOKUP_IP4_TO_CUCKOO;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_wait_in_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_WAIT_IN_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip1_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP1_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip2_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP2_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip3_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP3_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_insert_ip4_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_INSERT_IP4_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_wait_ip1_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_WAIT_IP1_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_wait_ip2_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_WAIT_IP2_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_wait_ip3_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_WAIT_IP3_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_wait_ip4_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_WAIT_IP4_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_nop_ip1_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_NOP_IP1_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_nop_ip2_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_NOP_IP2_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_nop_ip3_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_NOP_IP3_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_nop_ip4_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_NOP_IP4_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}

action recirculate_swapped_to_bloom() {
    ig_tm_md.ucast_egress_port = RECIRCULATE_PORT_SWAPPED_TO_BLOOM;
    ig_tm_md.bypass_egress = 0x1;
}