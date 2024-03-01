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
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.total_len = hdr.ipv4.total_len;
        meta.ip_proto = hdr.ipv4.protocol;
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
        meta.flag_ack    = hdr.tcp.ack;
        meta.flag_push   = hdr.tcp.psh;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        meta.flag_ack    = 0;
        meta.flag_push   = 0;
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

    /* Forward to a specific port */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    /* Do Nothing Action */
    action nop(){}

    /* Set final class upon voting */
    action set_final_class(bit<8> class_result) {
        hdr.ipv4.ttl = class_result;
        ipv4_forward(260);
    }

    /* Feature table actions */
    action SetCode0(bit<139> code0, bit<99> code1, bit<144> code2) {
        meta.codeword0[448:310] = code0;
        meta.codeword1[448:350] = code1;
        meta.codeword2[448:305] = code2;
    }
    action SetCode1(bit<97> code0, bit<147> code1, bit<164> code2) {
        meta.codeword0[309:213] = code0;
        meta.codeword1[349:203] = code1;
        meta.codeword2[304:141] = code2;
    }
    action SetCode2(bit<172> code0, bit<145> code1, bit<138> code2) {
        meta.codeword0[212:41] = code0;
        meta.codeword1[202:58] = code1;
        meta.codeword2[140:3] = code2;
    }
    action SetCode3(bit<9> code0, bit<17> code1, bit<1> code2) {
        meta.codeword0[40:32] = code0;
        meta.codeword1[57:41] = code1;
        meta.codeword2[2:2] = code2;
    }
    action SetCode4(bit<18> code0, bit<17> code1, bit<1> code2) {
        meta.codeword0[31:14] = code0;
        meta.codeword1[40:24] = code1;
        meta.codeword2[1:1] = code2;
    }
    action SetCode5(bit<14> code0, bit<24> code1, bit<1> code2) {
        meta.codeword0[13:0] = code0;
        meta.codeword1[23:0] = code1;
        meta.codeword2[0:0] = code2;
    }

    /* Feature tables */
	table table_feature0{
	    key = {meta.hdr_srcport: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 300;
        const default_action = nop();
	}
	table table_feature1{
        key = {meta.total_len: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 300;
        const default_action = nop();
	}
	table table_feature2{
	    key = {meta.hdr_dstport: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 400;
        const default_action = nop();
	}
	table table_feature3{
	    key = {meta.ip_proto: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 2;
        const default_action = nop();
	}
	table table_feature4{
	    key = {meta.flag_push: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 2;
        const default_action = nop();
	}
	table table_feature5{
	    key = {meta.flag_ack: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 2;
        const default_action = nop();
	}

    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;} 
	    size = 470;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;} 
	    size = 470;
        const default_action = nop();
	}
	table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;} 
	    size = 470;
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
        // apply feature tables to assign codes
        table_feature0.apply();
        table_feature1.apply();
        table_feature2.apply();
        table_feature3.apply();
        table_feature4.apply();
        table_feature5.apply();

        // apply code tables to assign labels
        code_table0.apply();
        code_table1.apply();
        code_table2.apply();

        // decide final class and forward
        voting_table.apply();

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
    apply {
        /* we do not update checksum because we used ttl field for stats*/
        pkt.emit(hdr.ethernet);
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
