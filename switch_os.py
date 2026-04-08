#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import time

from scapy.all import AsyncSniffer, BitField, Ether, Packet, ShortField, IntField, XShortField, bind_layers, sendp

from ltd_runtime import (
    CPU_METADATA_ETHER_TYPE,
    DEFAULT_CONTROLLER_HOST,
    DEFAULT_CONTROLLER_PORT,
    DEFAULT_DISCOVERY_PERIOD,
    DEFAULT_TOPOLOGY_PATH,
    DEFAULT_TRIGGER_SETTLE_TIME,
    LLDP_ETHER_TYPE,
    SimpleSwitchCliClient,
    decode_active_ports,
    load_topology,
)


class CpuMetadata(Packet):
    name = "LTDCpuMetadata"
    fields_desc = [
        BitField("fromCpu", 0, 8),
        IntField("switch_id", 0),
        XShortField("origEtherType", LLDP_ETHER_TYPE),
        ShortField("srcPort", 0),
    ]


class LTDLinkReport(Packet):
    name = "LTDLinkReport"
    fields_desc = [
        IntField("switch_id", 0),
        ShortField("port_id", 0),
    ]


bind_layers(Ether, CpuMetadata, type=CPU_METADATA_ETHER_TYPE)
bind_layers(CpuMetadata, LTDLinkReport)


def build_lldp_trigger_packet(switch_id):
    return Ether(
        dst="ff:ff:ff:ff:ff:ff",
        src="02:00:00:00:00:%02x" % (switch_id & 0xFF),
        type=CPU_METADATA_ETHER_TYPE,
    ) / CpuMetadata(
        fromCpu=1,
        switch_id=switch_id,
        origEtherType=LLDP_ETHER_TYPE,
        srcPort=0,
    )


class SwitchOSAgent:
    def __init__(self, topology, switch_name, controller_host, controller_port, discovery_period, settle_time):
        self.topology = topology
        self.switch_name = switch_name
        self.switch_id = int(topology.get_p4switch_id(switch_name))
        self.thrift_port = int(topology.get_thrift_port(switch_name))
        self.cpu_intf = topology.get_ctl_cpu_intf(switch_name)
        self.cpu_port = int(topology.get_cpu_port_index(switch_name))
        self.discovery_period = discovery_period
        self.settle_time = settle_time
        self.controller_addr = (controller_host, controller_port)
        self.client = SimpleSwitchCliClient(self.thrift_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.links = {}
        self.rule_handles = {}
        self.topology_dirty = False
        self.sniffer = None

    def initialize(self):
        self.client.table_clear("tb_init_switch_id")
        self.client.table_add("tb_init_switch_id", "init_switch_id", [], [str(self.switch_id)])

        self.client.table_clear("broadcast")
        self.client.table_add("broadcast", "set_mcast_grp", [str(self.cpu_port)], ["1"])

        data_ports = sorted(
            int(self.topology.node_to_node_port_num(self.switch_name, neighbor))
            for neighbor in self.topology.get_neighbors(self.switch_name)
        )
        self.client.mc_mgrp_create(1)
        node_handle = self.client.mc_node_create(0, data_ports)
        self.client.mc_node_associate(1, node_handle)

        self.client.table_clear("tb_check_link")
        self.client.register_reset("active_ports")
        print(
            "[switch_os:{}] thrift={} cpu_intf={} cpu_port={} mcast_ports={}".format(
                self.switch_name,
                self.thrift_port,
                self.cpu_intf,
                self.cpu_port,
                data_ports,
            )
        )

    def inject_trigger(self):
        trigger = build_lldp_trigger_packet(self.switch_id)
        print("[switch_os:{}] inject LLDP trigger".format(self.switch_name))
        sendp(trigger, iface=self.cpu_intf, verbose=False)

    def _print_active_ports(self, active_ports):
        if not active_ports:
            print("[switch_os:{}] active ports: <none>".format(self.switch_name))
            return

        port_text = ", ".join(
            "s{}:port {}".format(self.switch_id, port)
            for port in sorted(active_ports)
        )
        print("[switch_os:{}] active ports: {}".format(self.switch_name, port_text))

    def start(self):
        self.initialize()
        self.sniffer = AsyncSniffer(iface=self.cpu_intf, store=False, prn=self._handle_cpu_packet)
        self.sniffer.start()

    def stop(self):
        self.stop_event.set()
        if self.sniffer is not None:
            self.sniffer.stop()

    def process_cycle(self):
        active_vector = [self.client.register_read("active_ports", index) for index in range(4)]
        active_ports = decode_active_ports(active_vector)
        self._print_active_ports(active_ports)

        removed_ports = []
        with self.lock:
            stale_ports = sorted(set(self.links.keys()) - active_ports)
            for port in stale_ports:
                removed_ports.append(port)
                self._remove_known_link_locked(port)
            changed = self.topology_dirty
            self.topology_dirty = False
            snapshot = dict(self.links)
            unknown_active_ports = sorted(active_ports - set(snapshot.keys()))

        if removed_ports:
            print("[switch_os:{}] down links detected on ports {}".format(self.switch_name, removed_ports))

        if unknown_active_ports:
            print(
                "[switch_os:{}] active ports without learned links: {}".format(
                    self.switch_name,
                    ", ".join("s{}:port {}".format(self.switch_id, port) for port in unknown_active_ports),
                )
            )

        if changed:
            self._report_topology(snapshot)
        else:
            print("[switch_os:{}] no topology changes".format(self.switch_name))

        self.client.register_reset("active_ports")

    def _extract_cpu_link_report(self, packet):
        raw = bytes(packet)
        if len(raw) < 29:
            return None
        if int.from_bytes(raw[12:14], byteorder="big") != CPU_METADATA_ETHER_TYPE:
            return
        from_cpu = raw[14]
        if from_cpu != 0:
            return None
        ingress_port = int.from_bytes(raw[21:23], byteorder="big")
        src_switch_id = int.from_bytes(raw[23:27], byteorder="big")
        src_port_id = int.from_bytes(raw[27:29], byteorder="big")
        return ingress_port, src_switch_id, src_port_id

    def _handle_cpu_packet(self, packet):
        parsed = self._extract_cpu_link_report(packet)
        if parsed is None:
            return

        ingress_port, src_switch_id, src_port_id = parsed
        old_link = None

        with self.lock:
            current_link = self.links.get(ingress_port)
            new_link = (src_switch_id, src_port_id)
            if current_link == new_link:
                return

            if current_link is not None:
                old_link = current_link
                self._remove_known_link_locked(ingress_port)

            handle = self.client.table_add(
                "tb_check_link",
                "NoAction",
                [str(ingress_port), str(src_switch_id), str(src_port_id)],
                [],
            )
            self.links[ingress_port] = new_link
            self.rule_handles[ingress_port] = handle
            self.topology_dirty = True

        if old_link is None:
            print(
                "[switch_os:{}] new link on port {}: s{}:{} -> s{}:{}".format(
                    self.switch_name,
                    ingress_port,
                    src_switch_id,
                    src_port_id,
                    self.switch_id,
                    ingress_port,
                )
            )
        else:
            print(
                "[switch_os:{}] changed link on port {}: s{}:{} -> s{}:{} replaced by s{}:{} -> s{}:{}".format(
                    self.switch_name,
                    ingress_port,
                    old_link[0],
                    old_link[1],
                    self.switch_id,
                    ingress_port,
                    src_switch_id,
                    src_port_id,
                    self.switch_id,
                    ingress_port,
                )
            )

    def _remove_known_link_locked(self, ingress_port):
        handle = self.rule_handles.pop(ingress_port, None)
        old_link = self.links.pop(ingress_port, None)
        if handle is not None:
            self.client.table_delete("tb_check_link", handle)
        if old_link is not None:
            self.topology_dirty = True
        return old_link

    def _report_topology(self, adjacency):
        payload = {
            "switch_name": self.switch_name,
            "switch_id": self.switch_id,
            "adjacency": [
                {
                    "dst_port": port,
                    "src_switch_id": link[0],
                    "src_port_id": link[1],
                }
                for port, link in sorted(adjacency.items())
            ],
        }
        self.sock.sendto(json.dumps(payload).encode("utf-8"), self.controller_addr)
        print("[switch_os:{}] reported topology with {} links".format(self.switch_name, len(adjacency)))


def parse_args():
    parser = argparse.ArgumentParser(description="LTD switch OS process for BMv2")
    parser.add_argument("--topo", default=DEFAULT_TOPOLOGY_PATH, help="path to topology.json")
    parser.add_argument("--switch", action="append", dest="switches", help="switch name, e.g. s1; default is all P4 switches")
    parser.add_argument("--period", type=float, default=DEFAULT_DISCOVERY_PERIOD, help="discovery period in seconds")
    parser.add_argument("--settle-time", type=float, default=DEFAULT_TRIGGER_SETTLE_TIME, help="time to wait after trigger before reading registers")
    parser.add_argument("--controller-host", default=DEFAULT_CONTROLLER_HOST, help="controller IP address")
    parser.add_argument("--controller-port", type=int, default=DEFAULT_CONTROLLER_PORT, help="controller UDP port")
    return parser.parse_args()


def main():
    args = parse_args()
    topology = load_topology(args.topo)
    switch_names = sorted(args.switches or topology.get_p4switches().keys())
    agents = [
        SwitchOSAgent(
            topology=topology,
            switch_name=switch_name,
            controller_host=args.controller_host,
            controller_port=args.controller_port,
            discovery_period=args.period,
            settle_time=args.settle_time,
        )
        for switch_name in switch_names
    ]

    for agent in agents:
        agent.start()

    print("[switch_os] running for switches: {}".format(", ".join(switch_names)))
    try:
        while True:
            cycle_start = time.time()

            for agent in agents:
                agent.inject_trigger()

            time.sleep(args.settle_time)

            for agent in agents:
                try:
                    agent.process_cycle()
                except Exception as exc:
                    print("[switch_os:{}] cycle error: {}".format(agent.switch_name, exc))

            elapsed = time.time() - cycle_start
            remaining = max(0.0, args.period - elapsed)
            if remaining > 0:
                time.sleep(remaining)
    except KeyboardInterrupt:
        print("[switch_os] stopping")
    finally:
        for agent in agents:
            agent.stop()


if __name__ == "__main__":
    main()
