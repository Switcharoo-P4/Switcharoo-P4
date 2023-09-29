#ifndef _BLOOM_REGISTERS_
#define _BLOOM_REGISTERS_

Register<bit<32>, _>(1) insert_counter_on_bloom;
Register<bit<32>, _>(1) wait_counter_on_bloom;
Register<bit<32>, _>(1) wait_max_loops_on_bloom;
Register<bit<32>, _>(1) swap_counter_on_bloom;
Register<bit<32>, _>(1) swapped_counter_on_bloom;
Register<bit<32>, _>(1) lookup_counter_on_bloom;
Register<bit<32>, _>(1) nop_counter_on_bloom;
Register<bit<32>, _>(1) insert_max_loops_on_bloom;
Register<bit<32>, _>(1) from_insert_to_lookup_swap;
Register<bit<32>, _>(1) from_insert_to_lookup_bloom;
Register<bit<32>, _>(1) from_nop_to_wait;

Register<bit<32>, _>(1) bloom_packets_sent_out;
Register<bit<32>, _>(1) swap_dropped;

#endif /* _BLOOM_REGISTERS_ */