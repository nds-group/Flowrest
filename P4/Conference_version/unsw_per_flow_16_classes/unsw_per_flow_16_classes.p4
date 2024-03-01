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
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
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
    /* Check flag for classified flows */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
    update_classified_flag = {
        void apply(inout bit<8> classified_flag, out bit<8> output) {
            if (hdr.recirc.isValid()){
                classified_flag = hdr.recirc.class_result;
            }
            output = classified_flag;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_ID;
    /* Read and update flow ID */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    update_flow_ID = {
        void apply(inout bit<32> flow_ID) {
            flow_ID = meta.flow_ID;
        }
    };
    /* Only read flow ID */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    read_only_flow_ID = {
        void apply(inout bit<32> flow_ID, out bit<32> output) {
            output = flow_ID;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    /* Read and update timestamp of last packet of a flow */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_time_last_pkt)
    read_time_last_pkt = {
        void apply(inout bit<32> time_last_pkt, out bit<32> output) {
            output = time_last_pkt;
            time_last_pkt = ig_prsr_md.global_tstamp[31:0];
        }
    };

    /*  Registers for ML inference - features */
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_count;
    /* Read and update packet count */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_pkt_count)
    read_pkt_count = {
        void apply(inout bit<8> pkt_count, out bit<8> output) {
            pkt_count = pkt_count + 1;
            output = pkt_count;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_duration;
    /* Read and update flow duration */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_duration)
    read_flow_duration = {
        void apply(inout bit<32> flow_duration, out bit<32> output) {
            if (meta.is_first != 1){
                flow_duration = flow_duration + meta.iat;
            }
            output = flow_duration;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_iat_max;
    /* Read and update maximum packet interarrival time */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_iat_max)
    read_flow_iat_max = {
        void apply(inout bit<32> flow_iat_max, out bit<32> output) {
            if (meta.is_first != 1){
                if(meta.iat > flow_iat_max){
                    flow_iat_max = meta.iat;
                }
            }
            output = flow_iat_max;
        }
    };

    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_max;
    /* Read and update maximum packet length */
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


    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_min;
    /* Read and update minimum packet length */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(reg_pkt_len_min)
    read_pkt_len_min = {
        void apply(inout bit<16> pkt_len_min, out bit<16> output) {
            if (meta.is_first == 1){
                pkt_len_min = hdr.ipv4.total_len;
            }
            else if (hdr.ipv4.total_len < pkt_len_min){
                pkt_len_min  = hdr.ipv4.total_len;
            }
            output = pkt_len_min;
        }
    };


    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_len_total;
    /* Read and update total packet length */
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

    /* Declaration of the hashes*/
    Hash<bit<32>>(HashAlgorithm_t.CRC32)              flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)   idx_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID(bit<16> srcPort, bit<16> dstPort) {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }
    /* Calculate hash of the 5-tuple to use as register index */
    action get_register_index(bit<16> srcPort, bit<16> dstPort) {
        meta.register_index = idx_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }

    /* Recirculate packet via loopback port 68 */
    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recirc_port;
        hdr.recirc.setValid();
        hdr.recirc.class_result = meta.final_class;
        hdr.ethernet.ether_type = TYPE_RECIRC;
    }
    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe) {
        meta.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        meta.class2 = classe;
    }

    /* Compute packet interarrival time (IAT) */
    action get_iat_value(){
        meta.iat = ig_prsr_md.global_tstamp[31:0] - meta.time_last_pkt;
    }

    /* Forward to a specific port number */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    /* Do Nothing Action */
    action nop(){}

    /* Asign final class after voting and recirculate packet */
    action set_final_class(bit<8> class_result) {
        meta.final_class = class_result;
        recirculate(68);
    }

    /* Feature table actions - build codewords */
    action SetCode0(bit<67> code0, bit<62> code1, bit<54> code2) {
        meta.codeword0[348:282] = code0;
        meta.codeword1[348:287] = code1;
        meta.codeword2[348:295] = code2;
    }
    action SetCode1(bit<30> code0, bit<21> code1, bit<27> code2) {
        meta.codeword0[281:252] = code0;
        meta.codeword1[286:266] = code1;
        meta.codeword2[294:268] = code2;
    }
    action SetCode2(bit<61> code0, bit<65> code1, bit<52> code2) {
        meta.codeword0[251:191] = code0;
        meta.codeword1[265:201] = code1;
        meta.codeword2[267:216] = code2;
    }
    action SetCode3(bit<52> code0, bit<58> code1, bit<60> code2) {
        meta.codeword0[190:139] = code0;
        meta.codeword1[200:143] = code1;
        meta.codeword2[215:156] = code2;
    }
    action SetCode4(bit<39> code0, bit<47> code1, bit<35> code2) {
        meta.codeword0[138:100] = code0;
        meta.codeword1[142:96] = code1;
        meta.codeword2[155:121] = code2;
    }
    action SetCode5(bit<62> code0, bit<55> code1, bit<72> code2) {
        meta.codeword0[99:38] = code0;
        meta.codeword1[95:41] = code1;
        meta.codeword2[120:49] = code2;
    }
    action SetCode6(bit<38> code0, bit<41> code1, bit<49> code2) {
        meta.codeword0[37:0] = code0;
        meta.codeword1[40:0] = code1;
        meta.codeword2[48:0] = code2;
    }

    /* Feature tables */
	table table_feature0{
	    key = {meta.pkt_len_total: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 200;
        const default_action = nop();
	}
	table table_feature1{
        key = {meta.flow_duration[31:29]: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 16;
        const default_action = nop();
	}
	table table_feature2{
	    key = {meta.pkt_len_max: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 200;
        const default_action = nop();
	}
	table table_feature3{
	    key = {meta.hdr_srcport: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 200;
        const default_action = nop();
	}
	table table_feature4{
        key = {meta.pkt_len_min: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 100;
        const default_action = nop();
	}
	table table_feature5{
	    key = {meta.hdr_dstport: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 256;
        const default_action = nop();
	}
	table table_feature6{
	    key = {meta.flow_iat_max[31:27]: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 64;
        const default_action = nop();
	}


    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;} 
	    size = 370;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;} 
	    size = 370;
        const default_action = nop();
	}
	table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;} 
	    size = 370;
        const default_action = nop();
	}

    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
        }
        actions = {set_final_class; @defaultonly nop;}
        size = 6000;
        const default_action = nop();
    }


    apply {
            //compute flow_ID and hash index
            get_flow_ID(meta.hdr_srcport, meta.hdr_dstport);
            get_register_index(meta.hdr_srcport, meta.hdr_dstport);

            // modify timestamp register
            meta.time_last_pkt = read_time_last_pkt.execute(meta.register_index);

            // calculate iat
            get_iat_value();

            bit<32> tmp_flow_ID;

            // check if register array is empty
            if (meta.time_last_pkt == 0){ // this means it is the 1st pkt of the flow
                meta.is_first = 1;
                update_flow_ID.execute(meta.register_index);
                meta.pkt_count = read_pkt_count.execute(meta.register_index);
                meta.pkt_len_max = read_pkt_len_max.execute(meta.register_index);
                meta.pkt_len_min = read_pkt_len_min.execute(meta.register_index);
                meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);
                hdr.ipv4.ttl = 127; // we set ttl = 127 to track these packets downstream
                ipv4_forward(260);
            }

            else { // not the first packet - get flow_ID from register
                meta.is_first = 0;
                tmp_flow_ID = read_only_flow_ID.execute(meta.register_index);
                if(meta.flow_ID != tmp_flow_ID){ // hash collision
                    meta.is_hash_collision = 1;
                    hdr.ipv4.ttl = 255; // we set ttl = 255 to track hash collisions downstream
                    ipv4_forward(260);
                }
                else { // not first packet and not hash collision
                    //read and update packet count
                    meta.pkt_count = read_pkt_count.execute(meta.register_index);
                    //read and update feature registers - time-based features
                    meta.flow_iat_max = read_flow_iat_max.execute(meta.register_index);
                    meta.flow_duration = read_flow_duration.execute(meta.register_index);
                    //read and update feature registers - packet length-based features
                    meta.pkt_len_max = read_pkt_len_max.execute(meta.register_index);
                    meta.pkt_len_min = read_pkt_len_min.execute(meta.register_index);
                    meta.pkt_len_total = read_pkt_len_total.execute(meta.register_index);

                    // check if the number of packets/flow requirement is met
                    if(meta.pkt_count == 3){
                        // apply feature tables to assign codes
                        table_feature0.apply();
                        table_feature1.apply();
                        table_feature2.apply();
                        table_feature3.apply();
                        table_feature4.apply();
                        table_feature5.apply();
                        table_feature6.apply();

                        // apply code tables to assign labels
                        code_table0.apply();
                        code_table1.apply();
                        code_table2.apply();

                        // decide final class and recirculate
                        voting_table.apply();
                    }
                    // end of check on number of packets

                    else{ // this happens to first 2 packets and packet number 4 onwards
                        // register is updated with classification result so that forthcoming packets
                        // do not need to be classified anymore
                        meta.classified_flag = update_classified_flag.execute(meta.register_index);

                        if (meta.classified_flag != 0) {//No need to classify again - already classified
                            hdr.recirc.setInvalid(); // remove recirculation header
                            hdr.ethernet.ether_type = TYPE_IPV4; // replace ether type with IPV4
                            //set value of ttl to classification result (for stats only)
                            hdr.ipv4.ttl = meta.classified_flag;
                            ipv4_forward(260);
                		}
                        else{
                            // forward all other packets with ttl = 128 for tracking downstream
                            hdr.ipv4.ttl = 128;
                            ipv4_forward(260);
                        }
                    } //END OF CHECK FOR PREVIOUS CLASSIFICATION
                } //END OF CHECK ON IF NO COLLISION
            } // END OF CHECK ON WHETHER FIRST CLASS
        // } // END OF IPV4 VALIDITY CHECK
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
    // Checksum() ipv4_checksum;
    apply {
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
