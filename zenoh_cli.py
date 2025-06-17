"""Main entrypoint for this application"""

import sys
import json
import time
import atexit
import logging
import os
import pathlib
import warnings
import argparse
from base64 import b64decode, b64encode
from typing import Dict, Callable
import threading
import webbrowser
import tempfile
import re

import zenoh
import parse
import networkx as nx
from pyvis.network import Network
from jsonpointer import resolve_pointer


logger = logging.getLogger("zenoh-cli")


def info(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    info = session.info
    print(f"zid: {session.zid()}")
    print(f"routers: {info.routers_zid()}")
    print(f"peers: {info.peers_zid()}")


def scout(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    print("Scouting...")
    scout = zenoh.scout(what="peer|router")
    threading.Timer(1.0, lambda: scout.stop()).start()

    for hello in scout:
        print(hello)


def delete(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    for key in args.key:
        session.delete(key)


def put(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    # Validation
    if pattern := args.line:
        if "key" not in pattern and not args.key:
            parser.error(
                "A key must be specified either on the command line or as a pattern parameter."
            )
        elif "value" not in pattern and not args.value:
            parser.error(
                "A value must be specified either on the command line or as a pattern parameter."
            )
    else:
        if not args.key or not args.value:
            parser.error("A topic and a value must be specified on the command line.")

    encoder = ENCODERS[args.encoder]

    if pattern := args.line:
        line_parser = parse.compile(pattern)

        for line in sys.stdin:
            if result := line_parser.parse(line):
                key = args.key or result["key"]
                value = args.value or result["value"]
                try:
                    value = encoder(key, value)
                except Exception:
                    logger.exception("Encoder (%s) failed, skipping!", args.encoder)
                    continue

                session.put(
                    key_expr=key,
                    payload=value,
                    # encoding=args.encoding,
                    # priority=args.priority,
                    # congestion_control=args.congestion_control,
                )

            else:
                logger.error("Failed to parse line: %s", line)

    else:
        session.put(
            key_expr=args.key,
            payload=encoder(args.key, args.value),
            # encoding=args.encoding,
            # priority=args.priority,
            # congestion_control=args.congestion_control,
        )


def _print_sample_to_stdout(sample: zenoh.Sample, fmt: str, decoder: str):
    key = sample.key_expr
    payload = sample.payload.to_bytes()

    try:
        value = DECODERS[decoder](key, payload)
    except Exception:
        logger.exception("Decoder (%s) failed, skipping!", decoder)
        return

    sys.stdout.write(fmt.format(key=key, value=value).rstrip())
    sys.stdout.write("\n")
    sys.stdout.flush()


def get(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    encoder = ENCODERS[args.encoder]

    for response in session.get(
        args.selector,
        payload=encoder(args.selector, args.value) if args.value is not None else None,
    ):
        if response.ok:
            _print_sample_to_stdout(response.ok, args.line, args.decoder)
        else:
            logger.error(
                "Received error (%s) on get(%s)",
                response.err.payload.to_bytes(),
                args.selector,
            )


def subscribe(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    def listener(sample: zenoh.Sample):
        """Print received samples to stdout according to specified format"""
        _print_sample_to_stdout(sample, args.line, args.decoder)

    subscribers = [session.declare_subscriber(key, listener) for key in args.key]

    while True:
        try:
            time.sleep(0.1)
        except KeyboardInterrupt:
            sys.exit(0)


def network(
    session: zenoh.Session,
    config: zenoh.Config,
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
):
    def extract_ip(addr):
        # Extract IP from addresses like 'tcp/192.168.31.179:7447' or 'tcp/[::ffff:127.0.0.1]:50850'
        match = re.search(r'(?:\[::ffff:)?(\d+\.\d+\.\d+\.\d+)(?:\])?', addr)
        return match.group(1) if match else None

    graph = nx.Graph()

    me = str(session.info.zid())
    graph.add_node(me, whatami=config.get_json("mode"))

    # Scout the nearby network
    scout = zenoh.scout(what="client|peer|router")
    threading.Timer(1.0, lambda: scout.stop()).start()

    for answer in scout:
        logging.debug("--------------------------------")
        logging.debug("Scout answer: %s", answer)
        logging.debug("Scout answer zid: %s", answer.zid)
        logging.debug("Scout answer whatami: %s", answer.whatami)

        # Extract IPs from locators in scout answer
        scout_ips = set()
        for locator in answer.locators:
            if ip := extract_ip(locator):
                scout_ips.add(ip)

        graph.add_node(str(answer.zid), whatami=str(answer.whatami), ips=scout_ips)

    # Query routers for more information
    for response in session.get("@/*/router"):
        if response.ok:
            #logging.debug("Received router response: %s", response.ok.payload)
            data = json.loads(response.ok.payload.to_string())
            print(data)

            # Start adding edges and nodes
            zid = data["zid"]
            metadata = data["metadata"]

            # Extract IPs from locators
            router_ips = set()
            for locator in data.get("locators", []):
                if ip := extract_ip(locator):
                    router_ips.add(ip)

            # Update or add router node with IPs
            if zid in graph:
                graph.nodes[zid]["ips"].update(router_ips)
            else:
                graph.add_node(zid, whatami="router", metadata=metadata, ips=router_ips)

            for sess in data["sessions"]:
                peer = sess["peer"]
                whatami = sess["whatami"]

                # Extract IPs from links
                peer_ips = set()
                for link in sess["links"]:
                    if ip := extract_ip(link):
                        peer_ips.add(ip)

                # Update or add peer node with IPs
                if peer in graph:
                    graph.nodes[peer]["ips"].update(peer_ips)
                else:
                    graph.add_node(peer, whatami=whatami, ips=peer_ips)
                graph.add_edge(zid, peer, protocol="tcp")

        else:
            logger.error(
                "Received error (%s)",
                response.err.payload.to_bytes(),
            )
            pass

    # Create Pyvis network
    net = Network(height="1024", width="100%", bgcolor="#222222", font_color="white")

    # Group nodes by IP
    ip_groups = {}
    for node, attrs in graph.nodes(data=True):
        ips = attrs.get("ips", set())
        for ip in ips:
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(node)

    # Create group identifiers
    group_identifiers = {ip: f"G{i+1}" for i, ip in enumerate(sorted(ip_groups.keys()))}

    # Create legend nodes
    legend_y = 0
    for ip, group_id in group_identifiers.items():
        net.add_node(
            f"legend_{group_id}",
            label=f"{group_id}: {ip}",
            color="transparent",
            font={"size": 14, "color": "white"},
            x=0,
            y=legend_y,
            fixed=True
        )
        legend_y += 30

    # Node labels with group identifiers
    labels = {}
    for zid, attributes in graph.nodes(data=True):
        ips = attributes.get("ips", set())
        group_ids = [group_identifiers[ip] for ip in ips if ip in group_identifiers]
        group_suffix = f" ({', '.join(group_ids)})" if group_ids else ""

        if zid == me:
            labels[zid] = f"Me!{group_suffix}"
        else:
            base_label = resolve_pointer(attributes, f"/metadata{args.metadata_field}", zid[:5])
            labels[zid] = f"{base_label}{group_suffix}"

    # Add nodes with appropriate colors
    for node, attrs in graph.nodes(data=True):
        if node.startswith("legend_"):
            continue

        whatami = attrs.get("whatami", "")
        color = {
            "router": "#4682B4",  # steelblue
            "peer": "#F0F8FF",    # aliceblue
            "client": "#90EE90",  # lightgreen
        }.get(whatami, "#F08080")  # lightcoral for others

        if node == me:
            color = "#F08080"  # lightcoral for self

        net.add_node(
            node,
            label=labels.get(node, node[:5]),
            color=color,
            size=30 if whatami == "router" else 20
        )

    # Add edges with protocol labels
    for edge in graph.edges(data=True):
        source, target, data = edge
        protocol = data.get("protocol", "")
        net.add_edge(
            source,
            target,
            label=protocol,
            font={"size": 10, "color": "white"},
            color="white"
        )

    # Configure physics for better grouping
    net.set_options("""
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 200,
                "springConstant": 0.08
            },
            "maxVelocity": 50,
            "solver": "forceAtlas2Based",
            "timestep": 0.35,
            "stabilization": {
                "enabled": true,
                "iterations": 1000
            }
        }
    }
    """)

    # Create a temporary file and show the network
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        net.save_graph(tmp.name)
        webbrowser.open("file://" + tmp.name)
        print("Network visualization opened in your default web browser.")


# Text codec
def encode_from_text(key: str, value: str) -> bytes:
    return value.encode()


def decode_to_text(key: str, value: bytes) -> str:
    return value.decode()


# Base64 codec
def encode_from_base64(key: str, value: str) -> bytes:
    return b64decode(value.encode())


def decode_to_base64(key: str, value: bytes) -> str:
    return b64encode(value).decode()


# JSON codec
def encode_from_json(key: str, value: str) -> bytes:
    return encode_from_text(key, value)


def decode_to_json(key: str, value: bytes) -> str:
    # Makes sure the json is on a single line
    return json.dumps(json.loads(value))


ENCODERS: Dict[str, Callable] = {
    "text": encode_from_text,
    "base64": encode_from_base64,
    "json": encode_from_json,
}

DECODERS: Dict[str, Callable] = {
    "text": decode_to_text,
    "base64": decode_to_base64,
    "json": decode_to_json,
}


# Plugin handling
def gather_plugins():
    # NOTE: Python 3.8.x-3.9.x doesn't support the `group` keyword argument in
    # entry_points, in that case we fallback to `importlib_metadata`.
    if sys.version_info.minor >= 10:
        from importlib.metadata import entry_points
    else:
        logger.debug(
            "Falling back to importlib_metadata backport for python versions lower than 3.10"
        )
        from importlib_metadata import entry_points

    encoder_plugins = entry_points(group="zenoh_cli.codecs.encoders")
    decoder_plugins = entry_points(group="zenoh_cli.codecs.decoders")

    plugin_encoders = {}
    plugin_decoders = {}

    for plugin in encoder_plugins:
        plugin_encoders[plugin.name] = plugin

    for plugin in decoder_plugins:
        plugin_decoders[plugin.name] = plugin

    return plugin_encoders, plugin_decoders


def load_plugins(plugin_encoders, plugin_decoders):
    for name, plugin in plugin_encoders.items():
        try:
            ENCODERS[name] = plugin.load()
        except Exception:
            logger.exception("Failed to load encoder plugin with name: %s", name)

    for name, plugin in plugin_decoders.items():
        try:
            DECODERS[name] = plugin.load()
        except Exception:
            logger.exception("Failed to load decoder plugin with name: %s", name)


# Entrypoint
def main():
    plugin_encoders, plugin_decoders = gather_plugins()

    parser = argparse.ArgumentParser(
        prog="zenoh",
        description="Zenoh command-line client application",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--mode",
        choices=["peer", "client", "router"],
        default="peer",
        type=str,
    )
    parser.add_argument(
        "--connect",
        action="append",
        type=str,
        help="Endpoints to connect to.",
    )
    parser.add_argument(
        "--listen",
        action="append",
        type=str,
        help="Endpoints to listen on.",
    )

    parser.add_argument(
        "--config",
        type=pathlib.Path,
        help="A path to a configuration file.",
    )

    parser.add_argument(
        "--cfg",
        action="append",
        type=str,
        default=[],
        help="Configuration option according to 'PATH:VALUE'",
    )

    parser.add_argument(
        "--log-level",
        type=int,
        default=30,
        help="Log level: 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL 0=NOTSET",
    )

    # Subcommands
    subparsers = parser.add_subparsers(required=True)

    # Info subcommand
    info_parser = subparsers.add_parser("info")
    info_parser.set_defaults(func=info)

    # Network subcommand
    network_parser = subparsers.add_parser("network")
    network_parser.set_defaults(func=network)
    network_parser.add_argument(
        "--metadata-field",
        type=str,
        default="/name",
        help="JSON pointer to a field in a routers metadata configuration",
    )

    # Scout subcommand
    scout_parser = subparsers.add_parser("scout")
    scout_parser.add_argument("-w", "--what", type=str, default="peer|router")
    scout_parser.add_argument("-t", "--timeout", type=float, default=1.0)
    scout_parser.set_defaults(func=scout)

    # Delete subcommand
    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("-k", "--key", type=str, action="append", required=True)
    delete_parser.set_defaults(func=delete)

    # Common parser for all subcommands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--encoder",
        choices=list(ENCODERS.keys()) + list(plugin_encoders.keys()),
        default="text",
    )
    common_parser.add_argument(
        "--decoder",
        choices=list(DECODERS.keys()) + list(plugin_decoders.keys()),
        default="base64",
    )

    # Put subcommand
    put_parser = subparsers.add_parser("put", parents=[common_parser])
    put_parser.add_argument("-k", "--key", type=str, default=None)
    put_parser.add_argument("-v", "--value", type=str, default=None)
    put_parser.add_argument("--line", type=str, default=None)
    put_parser.set_defaults(func=put)

    # Subscribe subcommand
    subscribe_parser = subparsers.add_parser("subscribe", parents=[common_parser])
    subscribe_parser.add_argument(
        "-k", "--key", type=str, action="append", required=True
    )
    subscribe_parser.add_argument("--line", type=str, default="{value}")
    subscribe_parser.set_defaults(func=subscribe)

    # Get subcommand
    get_parser = subparsers.add_parser("get", parents=[common_parser])
    get_parser.add_argument("-s", "--selector", type=str, required=True)
    get_parser.add_argument("-v", "--value", type=str, default=None)
    get_parser.add_argument("--line", type=str, default="{value}")
    get_parser.set_defaults(func=get)

    # Parse arguments and start doing our thing
    args = parser.parse_args()

    # Setup logger
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s", level=args.log_level
    )
    logging.captureWarnings(True)
    warnings.filterwarnings("once")

    zenoh.init_log_from_env_or("error")

    # Load the plugins
    load_plugins(plugin_encoders, plugin_decoders)

    # Put together zenoh session configuration
    conf = (
        zenoh.Config.from_file(str(args.config))
        if args.config is not None
        else zenoh.Config()
    )
    if args.mode is not None:
        conf.insert_json5("mode", json.dumps(args.mode))
    if args.connect is not None:
        conf.insert_json5("connect/endpoints", json.dumps(args.connect))
    if args.listen is not None:
        conf.insert_json5("listen/endpoints", json.dumps(args.listen))

    for config_option in args.cfg:
        path, value = config_option.split(":", maxsplit=1)
        logger.info("Configuring with PATH=%s, VALUE=%s", path, value)
        try:
            conf.insert_json5(path, value)
        except:
            conf.insert_json5(path, json.dumps(value))

    # Construct session
    logger.info("Opening Zenoh session...")
    with zenoh.open(conf) as session:
        # Dispatch to correct function
        try:
            args.func(session, conf, parser, args)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
