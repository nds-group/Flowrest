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
    bit<1> is_first;
    bit<8> classified_flag;

    bit<32> flow_ID;
    bit<(INDEX_WIDTH)> register_index;
    bit<1> reg_status;

    // Timeout
    bit<32> now_timestamp;
    bit<32> age_value;

    bit<16> hdr_srcport;
    bit<16> hdr_dstport;

    bit<8> pkt_count;
    bit<32> time_last_pkt;

    bit<1> ack_flag;

    bit<16> pkt_len_total;
    bit<16> pkt_len_max;
    bit<8> ack_flag_count;

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;

    int<8> cert_t0;
    int<8> cert_t1;
    int<8> cert_t2;

    bit<8> final_class;

    bit<71> codeword0;
    bit<90> codeword1;
    bit<58> codeword2;

    bit<1> digest_info; // used for either class or collision info
    bit<2> f_action; // For flow_action table

}

struct flow_class_digest {  // maximum size allowed is 47 bytes
    ipv4_addr_t  source_addr;   // 32 bits
    ipv4_addr_t  destin_addr;   // 32 bits
    bit<16> source_port;
    bit<16> destin_port;
    bit<8> protocol;
    bit<8> flow_class;
    bit<(INDEX_WIDTH)> register_index; // To send register index info to the controller      
}
