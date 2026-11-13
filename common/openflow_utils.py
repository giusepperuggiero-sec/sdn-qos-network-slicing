"""Shared OpenFlow 1.3 constants, topology mappings, PacketOut helpers, and QoS classification."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

# Ethernet & IP protocol constants
ARP_ETH_TYPE = 0x0806
IPV4_ETH_TYPE = 0x0800
LLDP_ETH_TYPE = 0x88CC
STP_ETH_TYPE = 0x88E7
IP_PROTO_UDP = 17
UDP_PORT_STREAMING = 9999

# OpenFlow fallback constants (used by pure helpers / tests when Ryu is mocked)
DEFAULT_OFP_NO_BUFFER = 0xFFFFFFFF

# Statistical QoS classification thresholds (D-ITG streaming heuristic)
POLL_INTERVAL = 2
STATS_REQUEST_INTERVAL = 5
MIN_STAT_DURATION = 0.25  # Guard against sub-second bitrate spikes on newborn flows
VIDEO_MIN_AVG_PKT = 100
VIDEO_MIN_PPS = 1
VIDEO_MIN_BPS = 10_000
VIDEO_PRIORITY = 200
STATIC_SLICE_PRIORITY = 32768

# Default static diamond topology mappings matching topology/topology.py
DEFAULT_HOSTS: dict[str, dict[str, str]] = {
    "h1": {"mac": "00:00:00:00:00:01", "ip": "10.0.0.1"},
    "h2": {"mac": "00:00:00:00:00:02", "ip": "10.0.0.2"},
    "h3": {"mac": "00:00:00:00:00:03", "ip": "10.0.0.3"},
    "h4": {"mac": "00:00:00:00:00:04", "ip": "10.0.0.4"},
}

DEFAULT_PORT_MAP: dict[int, dict[str, Any]] = {
    1: {"hosts": [1, 2], "to_s2": 3, "to_s3": 4},  # S1 ingress switch
    2: {"to_s1": 1, "to_s4": 2},                   # S2 upper slice (10 Mbps)
    3: {"to_s1": 1, "to_s4": 2},                   # S3 lower slice (1 Mbps)
    4: {"hosts": [3, 4], "to_s2": 1, "to_s3": 2},  # S4 egress switch
}


def default_port_map() -> dict[int, dict[str, Any]]:
    """Return a mutable deep copy of the diamond topology port mapping."""
    return deepcopy(DEFAULT_PORT_MAP)


def add_flow(
    datapath: Any,
    priority: int,
    match: Any,
    actions: list[Any],
    *,
    buffer_id: int | None = None,
    idle_timeout: int = 0,
    flags: int = 0,
) -> None:
    """Install an OpenFlow 1.3 FlowMod rule using valid buffer_id semantics."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

    kwargs: dict[str, Any] = {
        "datapath": datapath,
        "priority": priority,
        "match": match,
        "instructions": inst,
        "idle_timeout": idle_timeout,
        "flags": flags,
    }
    no_buffer = getattr(ofproto, "OFP_NO_BUFFER", DEFAULT_OFP_NO_BUFFER)
    if buffer_id is not None and buffer_id != no_buffer:
        kwargs["buffer_id"] = buffer_id

    datapath.send_msg(parser.OFPFlowMod(**kwargs))


def install_table_miss(datapath: Any) -> None:
    """Install the default priority-0 table-miss rule sending unmatched packets to controller."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    add_flow(datapath, priority=0, match=match, actions=actions)


def install_service_slicing_rules(datapath: Any, port_map: dict[int, dict[str, Any]]) -> None:
    """Install priority-100 Upper Slice rules for UDP:9999 and Lower Slice best-effort rules."""
    parser = datapath.ofproto_parser
    dpid = datapath.id
    info = port_map.get(dpid, {})

    if dpid in (1, 4):
        port_up = info.get("to_s2")
        host_ports = info.get("hosts", [])
        if port_up is None or not host_ports:
            return

        # Outbound video from local hosts -> Upper Slice (S2)
        for host_port in host_ports:
            match = parser.OFPMatch(
                in_port=host_port,
                eth_type=IPV4_ETH_TYPE,
                ip_proto=IP_PROTO_UDP,
                udp_dst=UDP_PORT_STREAMING,
            )
            add_flow(datapath, priority=100, match=match, actions=[parser.OFPActionOutput(port_up)])

        # Inbound video arriving from Upper Slice (S2) -> local host ports
        match_in_up = parser.OFPMatch(
            in_port=port_up,
            eth_type=IPV4_ETH_TYPE,
            ip_proto=IP_PROTO_UDP,
            udp_dst=UDP_PORT_STREAMING,
        )
        actions_hosts = [parser.OFPActionOutput(port) for port in host_ports]
        add_flow(datapath, priority=100, match=match_in_up, actions=actions_hosts)

    elif dpid == 2:
        p_s1, p_s4 = info.get("to_s1"), info.get("to_s4")
        if p_s1 is not None and p_s4 is not None:
            for in_p, out_p in ((p_s1, p_s4), (p_s4, p_s1)):
                match = parser.OFPMatch(
                    in_port=in_p,
                    eth_type=IPV4_ETH_TYPE,
                    ip_proto=IP_PROTO_UDP,
                    udp_dst=UDP_PORT_STREAMING,
                )
                add_flow(datapath, priority=100, match=match, actions=[parser.OFPActionOutput(out_p)])

    elif dpid == 3:
        p_s1, p_s4 = info.get("to_s1"), info.get("to_s4")
        if p_s1 is not None and p_s4 is not None:
            for in_p, out_p in ((p_s1, p_s4), (p_s4, p_s1)):
                add_flow(
                    datapath,
                    priority=1,
                    match=parser.OFPMatch(in_port=in_p),
                    actions=[parser.OFPActionOutput(out_p)],
                )


def send_packet_out(
    datapath: Any,
    buffer_id: int,
    in_port: int,
    actions: list[Any],
    raw_data: bytes | None,
) -> None:
    """Send OFPPacketOut safely without violating OpenFlow 1.3 buffer_id/data rules."""
    if not actions:
        return

    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    no_buffer = getattr(ofproto, "OFP_NO_BUFFER", DEFAULT_OFP_NO_BUFFER)

    # OpenFlow 1.3 forbids attaching raw packet bytes when buffer_id references a switch buffer
    payload = raw_data if buffer_id == no_buffer else None
    out = parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=buffer_id,
        in_port=in_port,
        actions=actions,
        data=payload,
    )
    datapath.send_msg(out)


def get_controlled_flood_ports(
    dpid: int,
    in_port: int,
    port_map: dict[int, dict[str, Any]],
) -> list[int]:
    """Return loop-free flood ports confined to the lower slice (S3) to avoid diamond loops."""
    info = port_map.get(dpid, {})
    ports: set[int] = set()

    if dpid in (1, 4):
        ports.update(info.get("hosts", []))
        if info.get("to_s3") is not None:
            ports.add(info["to_s3"])
    elif dpid in (2, 3):
        if info.get("to_s1") is not None:
            ports.add(info["to_s1"])
        if info.get("to_s4") is not None:
            ports.add(info["to_s4"])

    return sorted(p for p in ports if p != in_port)


def handle_reactive_packet_in(
    *,
    msg: Any,
    packet_cls: Any,
    ethernet_cls: Any,
    mac_to_port: dict[int, dict[str, int]],
    port_map: dict[int, dict[str, Any]],
    logger: Any,
    drop_arp: bool = False,
    idle_timeout: int = 10,
) -> None:
    """Learn source MAC and install/flood reactive L2 forwarding safely without diamond loops."""
    datapath = msg.datapath
    parser = datapath.ofproto_parser
    dpid = datapath.id
    in_port = msg.match.get("in_port")
    if in_port is None:
        return

    pkt = packet_cls(msg.data)
    eth = pkt.get_protocol(ethernet_cls)
    if eth is None or eth.ethertype in (LLDP_ETH_TYPE, STP_ETH_TYPE):
        return

    if drop_arp and eth.ethertype == ARP_ETH_TYPE:
        logger.info(f"[ARP DROPPED] dpid={dpid} src={eth.src}")
        return

    mac_to_port.setdefault(dpid, {})[eth.src] = in_port
    dst_port = mac_to_port[dpid].get(eth.dst)

    if dst_port is not None:
        actions = [parser.OFPActionOutput(dst_port)]
        if dst_port != in_port:
            logger.info(f"[LEARNING] dpid={dpid} {eth.src} -> {eth.dst} out_port={dst_port}")
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
            add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=idle_timeout)
    else:
        flood_ports = get_controlled_flood_ports(dpid, in_port, port_map)
        actions = [parser.OFPActionOutput(port) for port in flood_ports]

    send_packet_out(datapath, msg.buffer_id, in_port, actions, msg.data)


def get_match_field(match_obj: Any, field: str) -> Any:
    """Safely extract a field from a Ryu OFPMatch or dict-like object."""
    if match_obj is None:
        return None
    if isinstance(match_obj, dict):
        return match_obj.get(field)
    try:
        return match_obj.get(field)
    except (AttributeError, TypeError, KeyError):
        return getattr(match_obj, field, None)


def compute_flow_metrics(
    packet_count: int,
    byte_count: int,
    duration_sec: int,
    duration_nsec: int = 0,
    min_duration: float = MIN_STAT_DURATION,
) -> tuple[float, float, float, float] | None:
    """Compute (duration_s, avg_pkt_bytes, pps, bps) or None if stats are empty/too short."""
    if packet_count <= 0:
        return None
    total_dur = max(0.0, float(duration_sec) + float(duration_nsec) / 1e9)
    if total_dur < min_duration:
        return None
    avg_pkt = float(byte_count) / float(packet_count)
    pps = float(packet_count) / total_dur
    bps = float(byte_count * 8) / total_dur
    return total_dur, avg_pkt, pps, bps


def is_video_flow(
    avg_pkt: float,
    pps: float,
    bps: float,
    min_avg_pkt: float = VIDEO_MIN_AVG_PKT,
    min_pps: float = VIDEO_MIN_PPS,
    min_bps: float = VIDEO_MIN_BPS,
) -> bool:
    """Determine whether statistical flow metrics match high-rate streaming traffic."""
    return avg_pkt >= min_avg_pkt and pps >= min_pps and bps >= min_bps


def resolve_adaptive_out_port(
    dpid: int,
    in_port: int | None,
    eth_dst: str | None,
    port_map: dict[int, dict[str, Any]],
    mac_to_port: dict[int, dict[str, int]],
) -> int | None:
    """Resolve loop-free upper-slice (S2) egress port for a classified video flow.

    Prevents S2 <-> S4 routing loops by directing ingress host traffic onto `to_s2`,
    forwarding through `S2` opposite the ingress port, and delivering `to_s2` traffic
    at `S1`/`S4` strictly to the learned destination host port (never back to `to_s2`).
    """
    info = port_map.get(dpid, {})
    if dpid in (1, 4):
        port_up = info.get("to_s2")
        hosts = set(info.get("hosts", []))
        if in_port in hosts:
            return port_up
        if in_port == port_up and eth_dst is not None:
            dst_port = mac_to_port.get(dpid, {}).get(eth_dst)
            if dst_port in hosts and dst_port != in_port:
                return dst_port
        return None

    if dpid == 2:
        p_s1 = info.get("to_s1")
        p_s4 = info.get("to_s4")
        if in_port == p_s1:
            return p_s4
        if in_port == p_s4:
            return p_s1
    return None
