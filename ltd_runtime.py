#!/usr/bin/env python3
import json
import os
import re
import subprocess
import threading
from pathlib import Path

CPU_METADATA_ETHER_TYPE = 0x080A
LLDP_ETHER_TYPE = 0x88CC
DEFAULT_CONTROLLER_HOST = "127.0.0.1"
DEFAULT_CONTROLLER_PORT = 50051
DEFAULT_DISCOVERY_PERIOD = 5.0
DEFAULT_TRIGGER_SETTLE_TIME = 1.0
DEFAULT_TOPOLOGY_PATH = "topology.json"

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SECUREINT_BMV2_DIR = os.path.join(THIS_DIR, "SecureINT-main", "BMv2")
STATE_DIR = os.path.join(THIS_DIR, ".runtime")


def ensure_runtime_state_dir():
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)


def ensure_p4utils_path():
    if SECUREINT_BMV2_DIR not in os.sys.path:
        os.sys.path.insert(0, SECUREINT_BMV2_DIR)


def load_topology(topology_path=DEFAULT_TOPOLOGY_PATH):
    ensure_p4utils_path()
    from p4utils.utils.helper import load_topo

    return load_topo(topology_path)


def decode_register_value(raw_value):
    if isinstance(raw_value, int):
        return raw_value

    value = str(raw_value).strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value)


def decode_active_ports(active_vector):
    active_ports = set()
    for block_index, block_value in enumerate(active_vector):
        value = decode_register_value(block_value)
        for bit_index in range(32):
            if (value >> bit_index) & 1:
                active_ports.add(block_index * 32 + bit_index + 1)
    return active_ports


def read_json_file(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_file(path, payload):
    ensure_runtime_state_dir()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


class SimpleSwitchCliClient:
    def __init__(self, thrift_port, cli_path=None):
        self.thrift_port = int(thrift_port)
        self.cli_path = cli_path or os.environ.get("SIMPLE_SWITCH_CLI", "simple_switch_CLI")
        self.lock = threading.Lock()

    def _run(self, commands):
        if isinstance(commands, str):
            commands = [commands]

        with self.lock:
            proc = subprocess.run(
                [self.cli_path, "--thrift-port", str(self.thrift_port)],
                input="\n".join(commands) + "\n",
                text=True,
                capture_output=True,
                check=False,
            )
        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(
                "simple_switch_CLI failed on thrift port {}.\nCommands:\n{}\nOutput:\n{}".format(
                    self.thrift_port,
                    "\n".join(commands),
                    output.strip(),
                )
            )
        return output

    def table_add(self, table_name, action_name, match_keys=None, action_params=None):
        match_keys = [str(item) for item in (match_keys or [])]
        action_params = [str(item) for item in (action_params or [])]
        command = "table_add {} {}".format(table_name, action_name)
        if match_keys:
            command += " " + " ".join(match_keys)
        command += " =>"
        if action_params:
            command += " " + " ".join(action_params)

        output = self._run(command)
        match = re.search(r"handle\s+(-?\d+)", output, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
        raise RuntimeError(
            "failed to parse entry handle from table_add output on thrift port {}.\nCommand: {}\nOutput:\n{}".format(
                self.thrift_port,
                command,
                output.strip(),
            )
        )

    def table_delete(self, table_name, entry_handle):
        if entry_handle is None:
            raise ValueError("entry_handle is required for table_delete")
        self._run("table_delete {} {}".format(table_name, int(entry_handle)))

    def table_clear(self, table_name):
        self._run("table_clear {}".format(table_name))

    def mc_mgrp_create(self, group_id):
        self._run("mc_mgrp_create {}".format(int(group_id)))

    def mc_node_create(self, rid, ports):
        ports = [str(int(port)) for port in ports]
        output = self._run("mc_node_create {} {}".format(int(rid), " ".join(ports)))
        match = re.search(r"handle\s+(-?\d+)", output, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
        raise RuntimeError(
            "failed to parse node handle from mc_node_create output on thrift port {}.\nOutput:\n{}".format(
                self.thrift_port,
                output.strip(),
            )
        )

    def mc_node_associate(self, group_id, node_handle):
        self._run("mc_node_associate {} {}".format(int(group_id), int(node_handle)))

    def register_read(self, register_name, index):
        output = self._run("register_read {} {}".format(register_name, int(index)))
        relevant_lines = [line.strip() for line in output.splitlines() if register_name in line]
        for line in reversed(relevant_lines):
            match = re.search(r"=\s*(0x[0-9a-fA-F]+|\d+)", line)
            if match:
                return decode_register_value(match.group(1))

        match = re.search(r"(0x[0-9a-fA-F]+|\d+)\s*$", output.strip())
        if match:
            return decode_register_value(match.group(1))

        raise RuntimeError(
            "failed to parse register_read output for {}[{}]: {}".format(
                register_name,
                index,
                output.strip(),
            )
        )

    def register_reset(self, register_name):
        self._run("register_reset {}".format(register_name))
