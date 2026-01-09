#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "util.p4"

#define ETHERTYPE_TO_CPU 0xBF01
#define ETHERTYPE_TO_CPU 0xBF01
    
//const PortId_t CPU_PORT = 192; // tofino with pipeline 2
// const PortId_t CPU_PORT = 320; // tofino with pipeline 4



typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_t;


const bit<16> TYPE_IPV4 = 0x800;
const bit<8> UDP_HEADER_LEN = 8;


const port_t CPU_PORT           = 500;
const bit<48> BROAD_CAST        = 0Xffffffffffff;

const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_LLDP         = 0x88cc;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/



header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header lldp_t {
    bit<32> switch_id;
    bit<16> port_id;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<32> switch_id;
    bit<16> origEtherType;
    bit<16> srcPort;
}


struct metadata {
    bit<32> switch_id;
    bit<9> ingress_port;
    bit<32> r;
    bit<6> shift_len;
}

struct headers {
    ethernet_t   ethernet;
    cpu_metadata_t    cpu_metadata;
    lldp_t       lldp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
        packet_in packet,
        out headers hdr,
        out metadata meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_LLDP: parse_lldp;
            default: accept;
        }
    }

    state parse_lldp {
        packet.extract(hdr.lldp);
        transition accept;
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition accept;
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/




/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control SwitchIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action init_switch_id(bit<32> switch_id){
        meta.switch_id = switch_id;
    }
    action drop() {
        ig_dprsr_md.drop_ctl = 0x001;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)ig_intr_md.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
        hdr.cpu_metadata.switch_id = meta.switch_id;
    }

    action cpu_meta_decap() {

        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
        //standard_metadata.egress_spec = ig_intr_md.ingress_port;
    }

    action send_to_cpu() {
        cpu_meta_encap();
        ig_tm_md.ucast_egress_port = CPU_PORT;
    }


    Register<bit<32>, bit<3>>(4) active_ports;
    
    RegisterAction<bit<32>, bit<3>, bit<32>>(active_ports) write_activc_ports = {
        void apply(inout bit<32> register_data, out bit<32> result){
            
            register_data = register_data ^ meta.r;
        }
    };

    action write_register(){

    }

    table tb_init_switch_id {
        actions = {
            init_switch_id;
            NoAction;
        }
        default_action = NoAction();
    }

    action set_mcast_grp(bit<16> mcast_grp) {
        ig_tm_md.mcast_grp_a = mcast_grp;
    }

    table tb_check_link {
        key = {
            ig_intr_md.ingress_port : exact;
            hdr.lldp.switch_id : exact;
            hdr.lldp.port_id : exact;
        }
        actions = {
            NoAction;
            send_to_cpu;
        }
        default_action = send_to_cpu();
    }

    table broadcast {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 32;
        default_action =  NoAction;
    }

    action shift_0() {;}
    action shift_1() {meta.r = 32w1 << 1;}
    action shift_2() {meta.r = 32w1 << 2;}
    action shift_3() {meta.r = 32w1 << 3;}
    action shift_4() {meta.r = 32w1 << 4;}
    action shift_5() {meta.r = 32w1 << 5;}
    action shift_6() {meta.r = 32w1 << 6;}
    action shift_7() {meta.r = 32w1 << 7;}
    action shift_8() {meta.r = 32w1 << 8;}
    action shift_9() {meta.r = 32w1 << 9;}
    action shift_10() {meta.r = 32w1 << 10;}
    action shift_11() {meta.r = 32w1 << 11;}
    action shift_12() {meta.r = 32w1 << 12;}
    action shift_13() {meta.r = 32w1 << 13;}
    action shift_14() {meta.r = 32w1 << 14;}
    action shift_15() {meta.r = 32w1 << 15;}
    action shift_16() {meta.r = 32w1 << 16;}
    action shift_17() {meta.r = 32w1 << 17;}
    action shift_18() {meta.r = 32w1 << 18;}
    action shift_19() {meta.r = 32w1 << 19;}
    action shift_20() {meta.r = 32w1 << 20;}
    action shift_21() {meta.r = 32w1 << 21;}
    action shift_22() {meta.r = 32w1 << 22;}
    action shift_23() {meta.r = 32w1 << 23;}
    action shift_24() {meta.r = 32w1 << 24;}
    action shift_25() {meta.r = 32w1 << 25;}
    action shift_26() {meta.r = 32w1 << 26;}
    action shift_27() {meta.r = 32w1 << 27;}
    action shift_28() {meta.r = 32w1 << 28;}
    action shift_29() {meta.r = 32w1 << 29;}
    action shift_30() {meta.r = 32w1 << 30;}
    action shift_31() {meta.r = 32w1 << 31;}

    table shift_c {
        key = {
            meta.shift_len: exact;
        }
        actions = {shift_0;shift_1;shift_2;shift_3;shift_4;shift_5;shift_6;shift_7;
        shift_8;shift_9;shift_10;shift_11;shift_12;shift_13;shift_14;shift_15;
        shift_16;shift_17;shift_18;shift_19;shift_20;shift_21;shift_22;shift_23;
        shift_24;shift_25;shift_26;shift_27;shift_28;shift_29;shift_30;shift_31;}

        const entries = {
            0:shift_0();
            1:shift_1();
            2:shift_2();
            3:shift_3();
            4:shift_4();
            5:shift_5();
            6:shift_6();
            7:shift_7();
            8:shift_8();
            9:shift_9();
            10:shift_10();
            11:shift_11();
            12:shift_12();
            13:shift_13();
            14:shift_14();
            15:shift_15();
            16:shift_16();
            17:shift_17();
            18:shift_18();
            19:shift_19();
            20:shift_20();
            21:shift_21();
            22:shift_22();
            23:shift_23();
            24:shift_24();
            25:shift_25();
            26:shift_26();
            27:shift_27();
            28:shift_28();
            29:shift_29();
            30:shift_30();
            31:shift_31();
        }
    }


    apply {
        tb_init_switch_id.apply();
        if (hdr.lldp.isValid()) {
            tb_check_link.apply();
            //get_lldp_count();
            
            bit<3> flag = 0;
            if (ig_intr_md.ingress_port < 32){
                meta.shift_len = (bit<6>) ig_intr_md.ingress_port;
                //write_activc_ports.execute(0);
                flag = 0;
            }
            else if (ig_intr_md.ingress_port < 64) {
                meta.shift_len = (bit<6>) (ig_intr_md.ingress_port - 32);
                //write_activc_ports.execute(1);
                flag = 1;
            }
            else if (ig_intr_md.ingress_port < 96) {
                meta.shift_len = (bit<6>) (ig_intr_md.ingress_port - 64);
                //write_activc_ports.execute(2);
                flag = 2;
            }
            else{
                meta.shift_len = (bit<6>) (ig_intr_md.ingress_port - 96);
                //write_activc_ports.execute(3);
                flag = 3;
            }
            shift_c.apply();
            write_activc_ports.execute(flag);
        }
        else if (hdr.cpu_metadata.isValid()){
            if (hdr.cpu_metadata.fromCpu == 1) {
                hdr.ethernet.dstAddr = BROAD_CAST;
                hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
                hdr.lldp.setValid();
                hdr.lldp.switch_id = meta.switch_id;

                broadcast.apply();
            }

        }
    }
}

control SwitchIngressDeparser(packet_out pkt,
                              inout headers hdr,
                              in metadata ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t 
                                ig_intr_dprsr_md
                              ) {

    apply {
        pkt.emit(hdr);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

parser EgressParser(packet_in        packet,
    /* User */
    out headers          hdr,
    out metadata         eg_md,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_LLDP: parse_lldp;
            default: accept;
        }
    }

    state parse_lldp {
        packet.extract(hdr.lldp);
        transition accept;
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition accept;
    }

}

control SwitchEgress(
        inout headers hdr,
        inout metadata meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {
        if (hdr.cpu_metadata.isValid() && hdr.cpu_metadata.fromCpu == 1) {
            hdr.cpu_metadata.setInvalid();
            hdr.lldp.port_id = (bit<16>) eg_intr_md.egress_port;
        }
    }
}

control EgressDeparser(packet_out pkt,
    /* User */
    inout headers hdr,
        in metadata eg_md,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);

    }
}

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    EgressParser(),
    SwitchEgress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;