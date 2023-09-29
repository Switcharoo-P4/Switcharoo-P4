#ifndef _CUCKOO_REGISTERS_
#define _CUCKOO_REGISTERS_

Register<bit<32>, _>(1) cuckoo_recirculated_packets;
Register<bit<32>, _>(1) insertions_counter;
Register<bit<32>, _>(1) expired_entry_table_1;
Register<bit<32>, _>(1) expired_entry_table_2;
Register<bit<32>, _>(1) valid_entry_table_2;
Register<bit<32>, _>(1) table_2_match_counter;
Register<bit<32>, _>(1) table_1_match_counter;
Register<bit<32>, _>(1) swap_creation;
#endif /* _CUCKOO_REGISTERS_ */