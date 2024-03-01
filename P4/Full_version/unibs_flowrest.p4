/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "./include/types.p4"
#include "./include/headers.p4"
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_RECIRC : parse_recirc;
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_recirc {
       pkt.extract(hdr.recirc);
       transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.hdr_dstport = hdr.tcp.dst_port;
        meta.hdr_srcport = hdr.tcp.src_port;
        meta.ack_flag = hdr.tcp.ack;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        meta.ack_flag = 0;
        transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Registers for flow management */
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_classified_flag;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
    update_classified_flag = {
        void apply(inout bit<8> classified_flag, out bit<8> output) {
            classified_flag = meta.final_class;
        }
    };
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
    read_classified_flag = {
        void apply(inout bit<8> classified_flag, out bit<8> output) {
            output = classified_flag;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_ID;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    update_flow_ID = {
        void apply(inout bit<32> flow_ID) {
            flow_ID = meta.flow_ID;
        }
    };
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    read_only_flow_ID = {
        void apply(inout bit<32> flow_ID, out bit<32> output) {
            output = flow_ID;
        }
    };

    Register<bit<1>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_status;
    /* Register read action */
    RegisterAction<bit<1>,bit<(INDEX_WIDTH)>,bit<1>>(reg_status)
    read_reg_status = {
        void apply(inout bit<1> status, out bit<1> output) {
            output = status;
            status = 1;
        }
    };

    //registers for ML inference - features
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_count;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_pkt_count)
    read_pkt_count = {
        void apply(inout bit<8> pkt_count, out bit<8> output) {
            if (meta.is_first != 1){
                pkt_count = pkt_count + 1;
            }
            else{
                pkt_count = 1;
            }
            output = pkt_count;

        }
    };

    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_total;
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_pkt_len_total)
    read_pkt_len_total = {
        void apply(inout bit<16> pkt_len_total, out bit<16> output) {
            if (meta.is_first == 1){
                pkt_len_total = hdr.ipv4.total_len;
            }
            else{
                pkt_len_total = pkt_len_total + hdr.ipv4.total_len;
            }
            output = pkt_len_total;
        }
    };

    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_max;
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_pkt_len_max)
    read_pkt_len_max = {
        void apply(inout bit<16> pkt_len_max, out bit<16> output) {
            if (meta.is_first == 1){
                pkt_len_max = hdr.ipv4.total_len;
            }
            else if (hdr.ipv4.total_len > pkt_len_max){
                pkt_len_max  = hdr.ipv4.total_len;
            }
            output = pkt_len_max;
        }
    };

    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_ack_flag_count;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_ack_flag_count)
    read_ack_flag_count = {
        void apply(inout bit<8> ack_flag_count, out bit<8> output) {
            if (meta.ack_flag == 1){
                ack_flag_count = ack_flag_count + 1;
            }
            output = ack_flag_count;
        }
    };

    // Timeout 
    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_time_occ;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_time_occ)
    read_reg_time_occ = {
        void apply(inout bit<32> time_last_pkt, out bit<32> output) {
            output = meta.now_timestamp - time_last_pkt; // s;
        }
    };
    /* Register update action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_time_occ)
    update_reg_time_occ = {
        void apply(inout bit<32> time_last_pkt) {
            time_last_pkt = meta.now_timestamp; // s
        }
    };

    /* Declaration of the hashes*/
    Hash<bit<32>>(HashAlgorithm_t.CRC32)              flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)   idx_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID(bit<16> srcPort, bit<16> dstPort) {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }
    /* Calculate hash of the 5-tuple to use as 1st register index */
    action get_register_index(bit<16> srcPort, bit<16> dstPort) {
        meta.register_index = idx_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }

    /* Recirculate packet via loopback port 68 */
    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recirc_port;
        hdr.recirc.setValid();
        hdr.ethernet.ether_type = TYPE_RECIRC;
    }
    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe, int<8> cert) {
        meta.class0 = classe;
        meta.cert_t0 = cert;
    }
    action SetClass1(bit<8> classe, int<8> cert) {
        meta.class1 = classe;
        meta.cert_t1 = cert;
    }
    action SetClass2(bit<8> classe, int<8> cert) {
        meta.class2 = classe;
        meta.cert_t2 = cert;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    /* Custom Do Nothing Action */
    action nop(){}

    action set_final_class(bit<8> class_result) {
        meta.final_class = class_result;
    }
    action set_flow_action(bit<2> f_action) {
        meta.f_action = f_action;
    }
    action set_miss_flow_action() {
        meta.f_action = 0;
    }

    /* Feature table actions */
    action SetCode0(bit<19> code0, bit<24> code1, bit<13> code2) {
        meta.codeword0[70:52] = code0;
        meta.codeword1[89:66] = code1;
        meta.codeword2[57:45] = code2;
    }
    action SetCode1(bit<16> code0, bit<21> code1, bit<11> code2) {
        meta.codeword0[51:36] = code0;
        meta.codeword1[65:45] = code1;
        meta.codeword2[44:34] = code2;
    }
    action SetCode2(bit<16> code0, bit<22> code1, bit<18> code2) {
        meta.codeword0[35:20] = code0;
        meta.codeword1[44:23] = code1;
        meta.codeword2[33:16] = code2;
    }
    action SetCode3(bit<14> code0, bit<20> code1, bit<14> code2) {
        meta.codeword0[19:6] = code0;
        meta.codeword1[22:3] = code1;
        meta.codeword2[15:2] = code2;
    }
    action SetCode4(bit<6> code0, bit<3> code1, bit<2> code2) {
        meta.codeword0[5:0] = code0;
        meta.codeword1[2:0] = code1;
        meta.codeword2[1:0] = code2;
    }

    /* Feature tables */
	table table_feature0{
	    key = {meta.hdr_dstport: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 48;
        const default_action = nop();
	}
	table table_feature1{
        key = {meta.pkt_len_max: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 48;
        const default_action = nop();
	}
	table table_feature2{
        key = {meta.pkt_len_total: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 64;
        const default_action = nop();
	} 
	table table_feature3{
        key = {hdr.ipv4.total_len: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 48;
        const default_action = nop();
	} 
	table table_feature4{
        key = {meta.ack_flag_count: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 8;
        const default_action = nop();
	} 

    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;}
	    size = 100;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;}
	    size = 100;
        const default_action = nop();
	}
    table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;}
	    size = 100;
        const default_action = nop();
	}

    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
        }
        actions = {set_final_class; @defaultonly nop;}
        size = 1000;
        const default_action = nop();
    }

    /* Forwarding-Inference Block Table */
    table flow_action_table {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            meta.hdr_srcport: exact;
            meta.hdr_dstport: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {set_flow_action; @defaultonly set_miss_flow_action;}
        size = 20000;
        const default_action = set_miss_flow_action();
    }

    apply {
            // compute the current time 
            meta.now_timestamp = (bit<32>)(ig_prsr_md.global_tstamp[47:20]);  //msec

            //compute flow_ID and hash index
            get_flow_ID(meta.hdr_srcport, meta.hdr_dstport);
            get_register_index(meta.hdr_srcport, meta.hdr_dstport);
            flow_action_table.apply();

            if (meta.f_action != 0) {   
                // Recirculated flow because of timeout collision
                if (hdr.recirc.isValid()){
                    meta.is_first = 1;
                    meta.reg_status = read_reg_status.execute(meta.register_index);
                    update_flow_ID.execute(meta.register_index);
                    meta.pkt_count = read_pkt_count.execute(meta.register_index);
                    meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);
                    meta.pkt_len_max = read_pkt_len_max.execute(meta.register_index);
                    meta.ack_flag_count = read_ack_flag_count.execute(meta.register_index);

                    update_reg_time_occ.execute(meta.register_index);
                    // Invalidate the recirculation header
                    hdr.recirc.setInvalid();
                    hdr.ethernet.ether_type = TYPE_IPV4;
                    ipv4_forward(260);
                }
                else{
                    // modify status register
                    meta.reg_status = read_reg_status.execute(meta.register_index);

                    // check if register array is empty
                    if (meta.reg_status == 0){ // we do not yet know this flow
                        meta.is_first = 1;
                        update_flow_ID.execute(meta.register_index);
                        meta.pkt_count = read_pkt_count.execute(meta.register_index);
                        meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);
                        meta.pkt_len_max = read_pkt_len_max.execute(meta.register_index);
                        meta.ack_flag_count = read_ack_flag_count.execute(meta.register_index);
                        update_reg_time_occ.execute(meta.register_index);
                        ipv4_forward(260);
                    }
                    else { // not the first packet - get flow_ID from register
                        bit<32> tmp_flow_ID;
                        tmp_flow_ID = read_only_flow_ID.execute(meta.register_index);
                        if(meta.flow_ID != tmp_flow_ID){ // hash collision
                            meta.age_value = read_reg_time_occ.execute(meta.register_index);
                            if (meta.age_value < timeout_threshold){
                                meta.final_class = 255;
                                ipv4_forward(260);
                            }
                            else{
                                // meta.digest_info = 127;
                                meta.final_class = 127;
                                recirculate(68);
                            }

                            ig_dprsr_md.digest_type = 1;        // activating the digest for statistics
                            
                        }
                        else { // not first packet and not hash collision
                            //read and update packet count
                            meta.is_first = 0;
                            meta.pkt_count = read_pkt_count.execute(meta.register_index);
                            //read and update feature registers
                            meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);
                            meta.pkt_len_max = read_pkt_len_max.execute(meta.register_index);
                            meta.ack_flag_count = read_ack_flag_count.execute(meta.register_index);

                            update_reg_time_occ.execute(meta.register_index);

                            // check if # of packets requirement is met
                            if(meta.pkt_count == 3){
                                // apply feature tables to assign codes
                                table_feature0.apply();
                                table_feature1.apply();
                                table_feature2.apply();
                                table_feature3.apply();
                                table_feature4.apply();

                                // apply code tables to assign labels
                                code_table0.apply();
                                code_table1.apply();
                                code_table2.apply();

                                voting_table.apply();

                                update_classified_flag.execute(meta.register_index);

                                // meta.digest_info = meta.final_class;
                                ig_dprsr_md.digest_type = 1;        // activating the digest after classification

                            }
                            // end of check on number of packets

                            else{ // this happens to first 2 packets and packet number 4 onwards
                                meta.classified_flag = read_classified_flag.execute(meta.register_index);
                                // if (meta.classified_flag != 0) {//No need to check again - already classified
                                //     ipv4_forward(260);
                                // }
                            } //END OF CHECK FOR PREVIOUS CLASSIFICATION
                            ipv4_forward(260);
                        } //END OF CHECK ON IF NO COLLISION
                    }
                } // END OF CHECK ON WHETHER FIRST CLASS
            }
            else{
                ipv4_forward(260);
            }
    } //END OF APPLY
} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest<flow_class_digest>() digest;

    apply {

        if (ig_dprsr_md.digest_type == 1) {
            digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, meta.final_class, meta.register_index});
        }
        /* we do not update checksum because we used ttl field for stats*/
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.recirc);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
#include "./include/egress.p4"

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
