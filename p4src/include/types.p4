#ifndef _TYPES_
#define _TYPES_

/* Protocols Enums */
enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    CUCKOO = 0xAAAA
}

enum bit<8> ip_proto_t {
    TCP = 6,
    UDP = 17
}

enum bit<8> cuckoo_ops_t {
    INSERT = 0x12,
    WAIT = 0xAA,
    NOP = 0xBB,
    LOOKUP = 0xCC,
    SWAPPED = 0xEE,
    SWAP = 0XFF
}

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

/* Struct to store L4 ports */
struct l4_lookup_t {
    bit<16> src_port;
    bit<16> dst_port;
}

/* Bloom Filter Entry Struct */
struct bloom_filter_t {
    bit<16> bloom_counter;
    bit<16> packet_to_send_out;
}

#endif /* _TYPES_ */