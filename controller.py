#!/usr/bin/env python3
import argparse
import json
import socket

from ltd_runtime import DEFAULT_CONTROLLER_HOST, DEFAULT_CONTROLLER_PORT


def format_link(dst_switch_id, dst_port, src_switch_id, src_port_id):
    return "s{}:{} -> s{}:{}".format(src_switch_id, src_port_id, dst_switch_id, dst_port)


class Controller:
    def __init__(self):
        self.adjacency = {}
        self.switch_names = {}

    def handle_report(self, payload):
        switch_id = int(payload["switch_id"])
        switch_name = payload.get("switch_name", "s{}".format(switch_id))
        new_links = {
            int(item["dst_port"]): (int(item["src_switch_id"]), int(item["src_port_id"]))
            for item in payload.get("adjacency", [])
        }

        old_links = self.adjacency.get(switch_id, {})
        events = self._diff_topology(switch_id, old_links, new_links)

        self.adjacency[switch_id] = new_links
        self.switch_names[switch_id] = switch_name

        print("[controller] report from {} (switch_id={}): {} links".format(switch_name, switch_id, len(new_links)))
        if events:
            for event in events:
                print("[controller] {}".format(event))
        else:
            print("[controller] no topology changes detected")
        self.print_topology()

    def _diff_topology(self, switch_id, old_links, new_links):
        events = []
        all_ports = sorted(set(old_links.keys()) | set(new_links.keys()))
        for port in all_ports:
            old_link = old_links.get(port)
            new_link = new_links.get(port)
            if old_link is None and new_link is not None:
                events.append("new link: {}".format(format_link(switch_id, port, new_link[0], new_link[1])))
            elif old_link is not None and new_link is None:
                events.append("removed link: {}".format(format_link(switch_id, port, old_link[0], old_link[1])))
            elif old_link is not None and new_link is not None and old_link != new_link:
                events.append(
                    "changed link on s{}:{}: {} => {}".format(
                        switch_id,
                        port,
                        format_link(switch_id, port, old_link[0], old_link[1]),
                        format_link(switch_id, port, new_link[0], new_link[1]),
                    )
                )
        return events

    def print_topology(self):
        print("[controller] current topology:")
        if not self.adjacency:
            print("[controller]   <empty>")
            return

        has_any_link = False
        for switch_id in sorted(self.adjacency.keys()):
            switch_name = self.switch_names.get(switch_id, "s{}".format(switch_id))
            links = self.adjacency[switch_id]
            print("[controller]   {}:".format(switch_name))
            if not links:
                print("[controller]     <no active links>")
                continue

            has_any_link = True
            for dst_port in sorted(links.keys()):
                src_switch_id, src_port_id = links[dst_port]
                print(
                    "[controller]     port {} <- s{}:{}".format(
                        dst_port,
                        src_switch_id,
                        src_port_id,
                    )
                )

        if not has_any_link:
            print("[controller]   <no active links>")


def parse_args():
    parser = argparse.ArgumentParser(description="LTD controller")
    parser.add_argument("--host", default=DEFAULT_CONTROLLER_HOST, help="controller listen address")
    parser.add_argument("--port", type=int, default=DEFAULT_CONTROLLER_PORT, help="controller UDP port")
    return parser.parse_args()


def main():
    args = parse_args()
    controller = Controller()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((args.host, args.port))

    print("[controller] listening on {}:{}".format(args.host, args.port))
    try:
        while True:
            message, address = server.recvfrom(65535)
            try:
                payload = json.loads(message.decode("utf-8"))
            except json.JSONDecodeError as exc:
                print("[controller] invalid report from {}: {}".format(address, exc))
                continue
            controller.handle_report(payload)
    except KeyboardInterrupt:
        print("[controller] stopping")
    finally:
        server.close()


if __name__ == "__main__":
    main()
