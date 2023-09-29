#ifndef _HEADERS_
#define _HEADERS_

#include "types.p4"

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    ip_proto_t protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv4_options_h {
    varbit<320> data;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header cuckoo_op_h {
    cuckoo_ops_t op;
}

header swap_entry_h {
    bit<32> ip_src_addr;
    bit<32> ip_dst_addr;
    bit<32> ports;
    bit<16> entry_value;
    bit<32> ts;
    bit<16> ts_2;
    bit<8> has_swap;
}

header cuckoo_counter_h {
    bit<16> assigned_counter;
    bit<7> recirc_counter;
    bit<1> is_assigned;
    bit<8> has_swap;
}

header swap_mirror_h {
    cuckoo_ops_t op;
}

/* Cuckoo Pipe Headers */
/* Ingress Headers */
struct cuckoo_ingress_headers_t {
    ethernet_h ethernet;
    cuckoo_op_h cuckoo_op;
    cuckoo_counter_h cuckoo_counter;
    swap_entry_h swap_entry;
    swap_entry_h carry_swap_entry;
    ipv4_h ipv4;
    ipv4_options_h ipv4_options;
    tcp_h tcp;
    udp_h udp;
}

/* Egress Headers */
struct cuckoo_egress_headers_t {
    ethernet_h ethernet;
    cuckoo_op_h cuckoo_op;
    cuckoo_counter_h cuckoo_counter;
    swap_entry_h swap_entry;
    swap_entry_h carry_swap_entry;
}

/* Bloom Pipe Headers */
/* Ingress Headers */
struct bloom_ingress_headers_t {
    ethernet_h ethernet;
    cuckoo_op_h cuckoo_op;
    cuckoo_counter_h cuckoo_counter;
    swap_entry_h swap_entry;
    swap_entry_h carry_swap_entry;
    ipv4_h ipv4;
    ipv4_options_h ipv4_options;
    tcp_h tcp;
    udp_h udp;
}

/* Egress Headers */
struct bloom_egress_headers_t {
}

#endif /* _HEADERS_ */