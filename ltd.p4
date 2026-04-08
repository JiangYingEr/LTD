#include <core.p4>
#include <v1model.p4>

typedef bit<48> mac_t;
typedef bit<9> port_t;

// CPU reports are sent to the BMv2 CPU port.
const port_t CPU_PORT = 3;

// LTD 使用自定义的 CPU 交互 EtherType，并采用精简的 LLDP 负载格式。
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_LLDP = 0x88cc;

// 在 BMv2 中，触发包通过组播复制到各端口，每个副本会在 egress 阶段被改写。
const mac_t LLDP_MULTICAST_MAC = 0x0180c200000e;
const mac_t LTD_SRC_MAC_PREFIX = 0x020000000000;

header ethernet_t {
    mac_t dstAddr;
    mac_t srcAddr;
    bit<16> etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<32> switch_id;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header lldp_t {
    bit<32> switch_id;
    bit<16> port_id;
}

struct headers {
    ethernet_t ethernet;
    cpu_metadata_t cpu_metadata;
    lldp_t lldp;
}

struct metadata {
    // switch_id 由控制面初始化一次，之后用于所有生成的 LLDP 报文。
    bit<32> switch_id;
    // 这两个字段用于在 128 端口活跃位图中定位具体的一个 bit。
    bit<32> active_block;
    bit<5> active_shift;
}

parser SwitchParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
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

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition accept;
    }

    state parse_lldp {
        packet.extract(hdr.lldp);
        transition accept;
    }
}

control SwitchIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // 用 4 个 32 位寄存器单元表示最多 128 个入端口的活跃状态。
    register<bit<32>>(4) active_ports;

    action init_switch_id(bit<32> switch_id) {
        meta.switch_id = switch_id;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        // fromCpu=0 表示这是 ASIC 生成并上送 CPU 的报告，不是 OS 注入的触发包。
        hdr.cpu_metadata.fromCpu = 0;
        hdr.cpu_metadata.switch_id = meta.switch_id;
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>) standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action generate_lldp_batch() {
        // 在 ingress 阶段消费触发头，并将其转换成内部 LLDP 报文格式。
        hdr.cpu_metadata.setInvalid();
        hdr.lldp.setValid();
        hdr.lldp.switch_id = meta.switch_id;
        // port_id 会在 egress 中针对每个复制副本分别填写。
        hdr.lldp.port_id = 0;
        hdr.ethernet.dstAddr = LLDP_MULTICAST_MAC;
        hdr.ethernet.srcAddr = LTD_SRC_MAC_PREFIX | (bit<48>) meta.switch_id;
        hdr.ethernet.etherType = TYPE_LLDP;
    }

    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    action update_active_ports() {
        bit<32> current;
        bit<32> mask;

        active_ports.read(current, meta.active_block);
        mask = 32w1 << meta.active_shift;
        active_ports.write(meta.active_block, current | mask);
    }

    table tb_init_switch_id {
        actions = {
            init_switch_id;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    table tb_check_link {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.lldp.switch_id : exact;
            hdr.lldp.port_id : exact;
        }
        actions = {
            NoAction;
            send_to_cpu;
        }
        // 已知链路项由交换机 OS/控制面下发；未命中表示新链路或链路发生变化。
        size = 1024;
        default_action = send_to_cpu();
    }

    table broadcast {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 32;
        default_action = NoAction();
    }

    apply {
        tb_init_switch_id.apply();

        if (hdr.cpu_metadata.isValid() && hdr.cpu_metadata.fromCpu == 1) {
            // 交换机 OS 只注入一个触发包，ASIC 在这里将其扩展为面向各端口的 LLDP 探测。
            generate_lldp_batch();
            broadcast.apply();
        } else if (hdr.lldp.isValid()) {
            // 先判断该 LLDP 是否匹配已知的单向链路。
            tb_check_link.apply();

            // 再将当前入端口标记为本轮发现周期内活跃。
            if (standard_metadata.ingress_port > 0 && standard_metadata.ingress_port <= 32) {
                meta.active_block = 0;
                meta.active_shift = (bit<5>) (standard_metadata.ingress_port - 1);
                update_active_ports();
            } else if (standard_metadata.ingress_port <= 64) {
                meta.active_block = 1;
                meta.active_shift = (bit<5>) (standard_metadata.ingress_port - 33);
                update_active_ports();
            } else if (standard_metadata.ingress_port <= 96) {
                meta.active_block = 2;
                meta.active_shift = (bit<5>) (standard_metadata.ingress_port - 65);
                update_active_ports();
            } else if (standard_metadata.ingress_port <= 128) {
                meta.active_block = 3;
                meta.active_shift = (bit<5>) (standard_metadata.ingress_port - 97);
                update_active_ports();
            }

            // 已知 LLDP 只负责更新活跃位图；只有未知链路事件才会上送 CPU。
            if (standard_metadata.egress_spec != CPU_PORT) {
                drop();
            }
        } else {
            // 该程序只处理 LTD 触发包和精简 LLDP 探测包，其它报文一律丢弃。
            drop();
        }
    }
}

control SwitchEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    table tb_port_block {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        // 供演示控制面使用，用于模拟链路 down/up 时的端口阻断。
        size = 128;
        default_action = NoAction();
    }

    apply {
        if (standard_metadata.egress_port != CPU_PORT) {
            tb_port_block.apply();
        }

        if (hdr.lldp.isValid() && standard_metadata.egress_port != CPU_PORT) {
            // 每个组播复制出来的副本都会在这里被改写成对应端口的 LLDP 报文。
            hdr.lldp.port_id = (bit<16>) standard_metadata.egress_port;
            hdr.ethernet.etherType = TYPE_LLDP;
        }
    }
}

control SwitchVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control SwitchComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control SwitchDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.lldp);
    }
}

V1Switch(
    SwitchParser(),
    SwitchVerifyChecksum(),
    SwitchIngress(),
    SwitchEgress(),
    SwitchComputeChecksum(),
    SwitchDeparser()
) main;
