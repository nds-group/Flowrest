/* -*- P4_16 -*- */

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

/*Custom header for recirculation*/
header recirc_h {
    bit<8>       class_result;
}

/* IPV4 header */
header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

/* TCP header */
header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/* UDP header */
header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    recirc_h     recirc;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {

    // flags for flow management
    bit<1> is_first;
    bit<8> classified_flag;
    bit<1> is_hash_collision;

    // ID and idex for flow management
    bit<32> flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    // features and necessary variables
    bit<8> pkt_count;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    bit<16> pkt_len_max;
    bit<16> pkt_len_min;
    bit<16> pkt_len_total;
    bit<32> flow_iat_max;
    bit<32> flow_duration;
    bit<32> time_last_pkt;
    bit<32> iat;

    // classification results of trees
    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
    bit<8> final_class;

    // code words for tree code tables
    bit<349> codeword0;
    bit<349> codeword1;
    bit<349> codeword2;
}
