#!/usr/bin/env python3
import argparse
import os

from ltd_runtime import (
    DEFAULT_TOPOLOGY_PATH,
    STATE_DIR,
    SimpleSwitchCliClient,
    ensure_runtime_state_dir,
    load_topology,
    read_json_file,
    write_json_file,
)

STATE_FILE = os.path.join(STATE_DIR, "link_simulation_state.json")


def parse_args():
    parser = argparse.ArgumentParser(description="Simulate link down/up by programming tb_port_block")
    parser.add_argument("--topo", default=DEFAULT_TOPOLOGY_PATH, help="path to topology.json")
    parser.add_argument("--switch", required=True, help="switch name, e.g. s1")
    parser.add_argument("--port", type=int, required=True, help="egress port to block/unblock")
    parser.add_argument("--action", choices=["down", "up"], required=True, help="down blocks the port, up removes the block")
    parser.add_argument("--single-ended", action="store_true", help="only operate on the specified switch port, do not touch the peer side")
    return parser.parse_args()


def resolve_endpoints(topology, switch_name, port, single_ended):
    endpoints = [(switch_name, int(port))]
    if single_ended:
        return endpoints

    try:
        neighbor = topology.port_to_node(switch_name, int(port))
    except Exception:
        return endpoints

    if not topology.isP4Switch(neighbor):
        return endpoints

    peer_port = int(topology.node_to_node_port_num(neighbor, switch_name))
    endpoints.append((neighbor, peer_port))
    return endpoints


def load_state():
    ensure_runtime_state_dir()
    return read_json_file(STATE_FILE, {})


def save_state(state):
    write_json_file(STATE_FILE, state)


def block_port(state, topology, switch_name, port):
    switch_state = state.setdefault(switch_name, {})
    key = str(port)
    if key in switch_state:
        print("[link_simulation] {} port {} is already blocked".format(switch_name, port))
        return

    thrift_port = int(topology.get_thrift_port(switch_name))
    client = SimpleSwitchCliClient(thrift_port)
    handle = client.table_add("tb_port_block", "SwitchEgress.drop", [str(port)], [])
    switch_state[key] = {"handle": handle}
    print("[link_simulation] blocked {} port {} (handle={})".format(switch_name, port, handle))


def unblock_port(state, topology, switch_name, port):
    switch_state = state.get(switch_name, {})
    key = str(port)
    entry = switch_state.get(key)
    if entry is None:
        print("[link_simulation] {} port {} is not recorded as blocked".format(switch_name, port))
        return

    thrift_port = int(topology.get_thrift_port(switch_name))
    client = SimpleSwitchCliClient(thrift_port)
    client.table_delete("tb_port_block", entry["handle"])
    del switch_state[key]
    if not switch_state:
        state.pop(switch_name, None)
    print("[link_simulation] unblocked {} port {} (handle={})".format(switch_name, port, entry["handle"]))


def main():
    args = parse_args()
    topology = load_topology(args.topo)
    endpoints = resolve_endpoints(topology, args.switch, args.port, args.single_ended)
    state = load_state()

    if args.action == "down":
        for switch_name, port in endpoints:
            block_port(state, topology, switch_name, port)
    else:
        for switch_name, port in endpoints:
            unblock_port(state, topology, switch_name, port)

    save_state(state)
    print(
        "[link_simulation] {} applied to endpoints: {}".format(
            args.action,
            ", ".join("{}:{}".format(name, port) for name, port in endpoints),
        )
    )


if __name__ == "__main__":
    main()
