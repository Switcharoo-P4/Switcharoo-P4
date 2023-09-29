/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "cuckoo_pipe/cuckoo.p4"
#include "cuckoo_pipe/parsers/ingress_parser.p4"
#include "cuckoo_pipe/parsers/egress_parser.p4"

Pipeline(
    CuckooIngressParser(),
    CuckooIngress(),
    CuckooIngressDeparser(),
    CuckooEgressParser(),
    CuckooEgress(),
    CuckooEgressDeparser()
) cuckoo;

#include "bloom_pipe/bloom.p4"
#include "bloom_pipe/parsers/ingress_parser.p4"
#include "bloom_pipe/parsers/egress_parser.p4"

Pipeline(
    BloomIngressParser(),
    BloomIngress(),
    BloomIngressDeparser(),
    BloomEgressParser(),
    BloomEgress(),
    BloomEgressDeparser()
) bloom;

Switch(cuckoo, bloom) main;